"""
meraki_api.py — Meraki Dashboard API client for the onboarding tool.

Covers:
  - GET  /organizations/{orgId}                          verify API key + org
  - GET  /organizations/{orgId}/networks                 list networks
  - POST /organizations/{orgId}/inventory/claim          claim Cloud IDs into org inventory
  - GET  /organizations/{orgId}/inventory/devices        verify device appeared in inventory
  - POST /networks/{networkId}/devices/claim             add devices to network with operating mode
  - GET  /networks/{networkId}/devices                   verify device in network

API docs:
  https://developer.cisco.com/meraki/api-v1/
  https://documentation.meraki.com/Switching/Cloud_Management_with_IOS_XE/Install_and_Get_Started/Operating_mode_claim_to_network_API_endpoint
"""

import asyncio
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)

BASE_URL = "https://api.meraki.com/api/v1"
# Rate limit: claim endpoints allow 10 requests per 5 minutes
CLAIM_RATE_LIMIT_DELAY = 2  # seconds between claim calls as a safety buffer


class MerakiAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class MerakiDashboardClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self.headers,
            timeout=30.0,
            follow_redirects=True,  # Meraki API uses redirects
        )

    async def _get(self, path: str, params: dict = None) -> dict | list:
        async with self._client() as client:
            resp = await client.get(f"{BASE_URL}{path}", params=params)
            self._raise_for_status(resp)
            return resp.json()

    async def _post(self, path: str, body: dict) -> dict | list:
        async with self._client() as client:
            resp = await client.post(f"{BASE_URL}{path}", json=body)
            self._raise_for_status(resp)
            return resp.json()

    def _raise_for_status(self, resp: httpx.Response):
        if resp.status_code >= 400:
            try:
                detail = resp.json()
                msg = detail.get("errors", [str(detail)])[0] if isinstance(detail, dict) else str(detail)
            except Exception:
                msg = resp.text or f"HTTP {resp.status_code}"
            raise MerakiAPIError(resp.status_code, msg)

    # ------------------------------------------------------------------ #
    #  Organization                                                        #
    # ------------------------------------------------------------------ #

    async def get_organization(self, org_id: str) -> dict:
        """Verify the org exists and the API key has access."""
        return await self._get(f"/organizations/{org_id}")

    async def list_networks(self, org_id: str) -> list:
        """List all networks in an organization."""
        return await self._get(f"/organizations/{org_id}/networks")

    async def get_network(self, network_id: str) -> dict:
        """Get a specific network by ID."""
        return await self._get(f"/networks/{network_id}")

    # ------------------------------------------------------------------ #
    #  Inventory claim                                                     #
    # ------------------------------------------------------------------ #

    async def claim_into_org_inventory(self, org_id: str, cloud_ids: list[str]) -> dict:
        """
        POST /organizations/{orgId}/inventory/claim
        Claim Cloud IDs (serials) into the organization inventory.
        Must be done before adding to a network.
        Rate limit: 10 requests per 5 minutes.
        """
        logger.info("Claiming %d device(s) into org %s inventory", len(cloud_ids), org_id)
        body = {"serials": cloud_ids}
        return await self._post(f"/organizations/{org_id}/inventory/claim", body)

    async def get_inventory_device(self, org_id: str, serial: str) -> Optional[dict]:
        """
        GET /organizations/{orgId}/inventory/devices
        Check if a specific Cloud ID is in the org inventory.
        """
        devices = await self._get(
            f"/organizations/{org_id}/inventory/devices",
            params={"serials[]": serial}
        )
        return devices[0] if devices else None

    # ------------------------------------------------------------------ #
    #  Network claim — with operating mode                                 #
    # ------------------------------------------------------------------ #

    async def add_devices_to_network(
        self,
        network_id: str,
        devices: list[dict],  # [{"cloud_id": "...", "mode": "device"|"cloud", "username": "...", "password": "...", "secret": "..."}]
        add_atomically: bool = False,
    ) -> dict:
        """
        POST /networks/{networkId}/devices/claim
        Add devices to a network with the correct operating mode.

        Per Meraki docs:
          - Cloud Config mode → device_mode = "managed"   (triggers factory reset)
          - Device Config mode → device_mode = "monitored" (credentials required)

        Source: https://documentation.meraki.com/Switching/Cloud_Management_with_IOS_XE/
                Install_and_Get_Started/Operating_mode_claim_to_network_API_endpoint
        """
        serials = [d["cloud_id"] for d in devices]

        details_by_device = []
        for d in devices:
            cloud_id = d["cloud_id"]
            mode = d.get("mode", "device")

            if mode == "cloud":
                # Cloud Configuration mode → "managed" → triggers factory reset
                details_by_device.append({
                    "serial": cloud_id,
                    "details": [
                        {"name": "device mode", "value": "managed"},
                    ]
                })
            else:
                # Device Configuration mode → "monitored" → credentials required
                dev_details = [
                    {"name": "device mode",  "value": "monitored"},
                    {"name": "username",     "value": d.get("username", "")},
                    {"name": "password",     "value": d.get("password", "")},
                ]
                # Enable/secret password is optional
                if d.get("secret"):
                    dev_details.append({"name": "enable password", "value": d["secret"]})
                details_by_device.append({
                    "serial": cloud_id,
                    "details": dev_details,
                })

        body = {
            "serials": serials,
            "addAtomically": add_atomically,
            "detailsByDevice": details_by_device,
        }
        logger.info(
            "Adding %d device(s) to network %s (atomically=%s)",
            len(devices), network_id, add_atomically
        )
        return await self._post(f"/networks/{network_id}/devices/claim", body)

    async def get_network_devices(self, network_id: str) -> list:
        """GET /networks/{networkId}/devices — verify devices appear in the network."""
        return await self._get(f"/networks/{network_id}/devices")

    async def get_device(self, serial: str) -> dict:
        """GET /devices/{serial} — get full details for a single device."""
        return await self._get(f"/devices/{serial}")

    async def verify_device_mode(self, cloud_id: str, org_id: str, expected_mode: str) -> tuple[bool, str]:
        """
        Confirm a device's operating mode in Dashboard matches expected.

        Uses GET /organizations/{orgId}/inventory/devices to look up the device
        by its Cloud ID (serial). The operating mode is stored as:
          {"name": "Cloud configuration", "value": "monitoring"}  → Device Config (monitored)
          {"name": "Cloud configuration", "value": "management"}  → Cloud Config (managed)

        expected_mode: 'monitored' (Device Config) or 'managed' (Cloud Config)
        Returns (match: bool, actual_value_or_error: str)
        """
        # Map our mode names to what Dashboard stores in "Cloud configuration"
        MODE_MAP = {
            "monitored": "monitoring",
            "managed":   "management",
        }
        expected_value = MODE_MAP.get(expected_mode.lower(), expected_mode.lower())

        try:
            inv = await self.get_inventory_device(org_id, cloud_id)
            if inv is None:
                return False, f"device '{cloud_id}' not found in org inventory"

            details = inv.get("details", [])
            detail_map = {d["name"]: d["value"] for d in details if "name" in d and "value" in d}

            actual_value = detail_map.get("Cloud configuration")
            if actual_value is None:
                return False, "'Cloud configuration' not yet in inventory details (still syncing)"

            match = actual_value.lower() == expected_value.lower()
            return match, actual_value

        except MerakiAPIError as e:
            return False, f"API error {e.status_code}: {e.message}"
        except Exception as e:
            return False, str(e)

    # ------------------------------------------------------------------ #
    #  Convenience helpers                                                 #
    # ------------------------------------------------------------------ #

    async def verify_api_key(self, org_id: str) -> tuple[bool, str]:
        """Returns (success, org_name_or_error)."""
        try:
            org = await self.get_organization(org_id)
            return True, org.get("name", org_id)
        except MerakiAPIError as e:
            if e.status_code == 401:
                return False, "Invalid API key"
            elif e.status_code == 404:
                return False, f"Organization {org_id} not found"
            return False, e.message
        except Exception as e:
            return False, str(e)

    async def full_onboard(
        self,
        org_id: str,
        network_id: str,
        devices: list[dict],
        add_atomically: bool = False,
        log_fn=None,
    ) -> dict:
        """
        Full Dashboard API onboarding flow:
          1. Claim Cloud IDs into org inventory
          2. Wait briefly for inventory to register
          3. Add devices to network with correct operating mode

        Returns summary dict with claim + network results.
        """

        async def log(msg, color="info"):
            logger.info(msg)
            if log_fn:
                await log_fn(msg, color)

        results = {
            "org_claim": None,
            "network_claim": None,
            "errors": [],
        }

        cloud_ids = [d["cloud_id"] for d in devices]

        # Step 1: Claim into org inventory
        await log(f"[Meraki API] Claiming {len(cloud_ids)} device(s) into org inventory…", "accent")
        try:
            claim_resp = await self.claim_into_org_inventory(org_id, cloud_ids)
            results["org_claim"] = claim_resp
            await log(f"[Meraki API] ✓ Claimed into org inventory: {cloud_ids}", "success")
        except MerakiAPIError as e:
            msg = f"[Meraki API] ✗ Org inventory claim failed: {e.message}"
            await log(msg, "error")
            results["errors"].append(msg)
            return results
        except Exception as e:
            msg = f"[Meraki API] ✗ Unexpected error during org claim: {e}"
            await log(msg, "error")
            results["errors"].append(msg)
            return results

        # Step 2: Brief wait — newly claimed devices take a moment to appear
        await log("[Meraki API] Waiting for inventory to register (15s)…", "warn")
        await asyncio.sleep(15)

        # Step 3: Add to network with operating mode
        mode_labels = {d["cloud_id"]: ("managed" if d.get("mode") == "cloud" else "monitored") for d in devices}
        await log(
            f"[Meraki API] Adding devices to network {network_id} "
            f"(modes: {', '.join(f'{k}→{v}' for k, v in mode_labels.items())})…",
            "accent"
        )
        try:
            network_resp = await self.add_devices_to_network(network_id, devices, add_atomically)
            results["network_claim"] = network_resp
            await log(f"[Meraki API] ✓ Devices added to network {network_id}", "success")

            # Mode-specific follow-up messages
            for d in devices:
                if d.get("mode") == "cloud":
                    await log(
                        f"[Meraki API] ⚠  {d['cloud_id']}: Cloud Config (managed) — "
                        "factory reset will begin. Do NOT power cycle!", "warn"
                    )
                else:
                    await log(
                        f"[Meraki API] ✓  {d['cloud_id']}: Device Config (monitored) — "
                        "Dashboard will push config automatically.", "success"
                    )
        except MerakiAPIError as e:
            msg = f"[Meraki API] ✗ Network claim failed (HTTP {e.status_code}): {e.message}"
            await log(msg, "error")
            results["errors"].append(msg)
        except Exception as e:
            msg = f"[Meraki API] ✗ Unexpected error adding to network: {e}"
            await log(msg, "error")
            results["errors"].append(msg)

        return results

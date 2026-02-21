"""
bulk_orchestrator.py — Coordinates SSH checks across multiple devices,
then calls the Meraki Dashboard API to claim and add them all to a network.

Flow:
  1. SSH into each device concurrently (up to MAX_CONCURRENT at a time)
  2. Run all prerequisite checks + issue 'service meraki connect'
  3. Collect Cloud IDs from all successful devices
  4. Call Meraki API: claim into org inventory
  5. Call Meraki API: add to network with correct operating mode + credentials

Source for API payloads:
  https://documentation.meraki.com/Switching/Cloud_Management_with_IOS_XE/
  Install_and_Get_Started/Operating_mode_claim_to_network_API_endpoint
"""

import asyncio
import logging
import uuid
from datetime import datetime

from models import DeviceRequest, BulkRequest, BulkJobStatus, CheckResult
from device_checker import DeviceChecker
from meraki_api import MerakiDashboardClient, MerakiAPIError

logger = logging.getLogger(__name__)

MAX_CONCURRENT = 5  # Max parallel SSH sessions


class BulkOrchestrator:
    def __init__(self, req: BulkRequest, ws=None):
        self.req      = req
        self.ws       = ws
        self.job_id   = str(uuid.uuid4())
        self.status   = BulkJobStatus(
            job_id=self.job_id,
            status="queued",
            total=len(req.devices),
        )
        self._lock    = asyncio.Lock()

    async def log(self, msg: str, color: str = "info"):
        logger.info("[BULK %s] %s", self.job_id[:8], msg)
        if self.ws:
            await self.ws.send_json({"type": "bulk_log", "msg": msg, "color": color})

    async def send_status(self):
        if self.ws:
            await self.ws.send_json({"type": "bulk_status", "status": self.status.model_dump()})

    # ------------------------------------------------------------------ #
    #  Phase 1 — SSH checks per device                                     #
    # ------------------------------------------------------------------ #

    async def _check_one(self, req: DeviceRequest, semaphore: asyncio.Semaphore) -> CheckResult:
        async with semaphore:
            checker = DeviceChecker(req)
            result = await checker.run()
            async with self._lock:
                self.status.completed += 1
                self.status.results.append(result)
                if result.status == "done":
                    self.status.succeeded += 1
                else:
                    self.status.failed += 1
            await self.send_status()
            return result

    async def run_ssh_phase(self) -> list[CheckResult]:
        """SSH into all devices concurrently (bounded by MAX_CONCURRENT)."""
        await self.log(
            f"Phase 1 — SSH checks: {len(self.req.devices)} device(s), "
            f"max {MAX_CONCURRENT} concurrent", "accent"
        )
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        tasks = [self._check_one(dev, semaphore) for dev in self.req.devices]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)

    # ------------------------------------------------------------------ #
    #  Phase 2 — Meraki Dashboard API                                      #
    # ------------------------------------------------------------------ #

    async def run_api_phase(self, ssh_results: list[CheckResult]):
        """
        For all devices that successfully obtained a Cloud ID,
        claim into org inventory then add to network with the correct mode.
        """
        successful = [r for r in ssh_results if r.status == "done" and r.cloud_id]
        if not successful:
            await self.log("No successful devices to claim — skipping Dashboard API phase", "warn")
            return

        await self.log(
            f"Phase 2 — Meraki Dashboard API: claiming {len(successful)} device(s) "
            f"to org {self.req.org_id} / network {self.req.network_id}", "accent"
        )

        # Instantiate client here (not in __init__) so unit test mocks intercept correctly
        self.meraki = MerakiDashboardClient(self.req.meraki_api_key)

        # Verify API key first
        await self.log("Verifying Meraki API key and organization access…", "muted")
        ok, org_name = await self.meraki.verify_api_key(self.req.org_id)
        if not ok:
            await self.log(f"✗ Meraki API access failed: {org_name}", "error")
            self.status.meraki_claim_result = {"error": org_name}
            return
        await self.log(f"Meraki API key valid — org: {org_name} ✓", "success")

        # Build device payload for the API
        # Each device needs: cloud_id, mode, and credentials (for device config mode)
        device_map = {r.host: r for r in successful}
        req_map    = {d.host: d for d in self.req.devices}

        api_devices = []
        for result in successful:
            req = req_map.get(result.host)
            api_devices.append({
                "cloud_id": result.cloud_id,
                "mode":     result.mode,
                "username": req.username if req else "",
                "password": req.password if req else "",
                "secret":   req.secret   if req else None,
            })

        # Run the full Meraki API onboarding flow
        api_result = await self.meraki.full_onboard(
            org_id=self.req.org_id,
            network_id=self.req.network_id,
            devices=api_devices,
            add_atomically=self.req.add_atomically,
            log_fn=self.log,
        )

        self.status.meraki_claim_result  = api_result.get("org_claim")
        self.status.meraki_network_result = api_result.get("network_claim")

        if not api_result.get("errors"):
            await self.log(
                f"✓ All {len(successful)} device(s) claimed and added to network "
                f"{self.req.network_id} successfully", "success"
            )
        else:
            for err in api_result["errors"]:
                await self.log(f"✗ API error: {err}", "error")

    # ------------------------------------------------------------------ #
    #  Main orchestrator                                                   #
    # ------------------------------------------------------------------ #

    async def run(self) -> BulkJobStatus:
        self.status.status = "running"
        await self.send_status()

        await self.log(
            f"Starting bulk onboarding — {len(self.req.devices)} device(s) "
            f"→ org {self.req.org_id} / network {self.req.network_id}", "accent"
        )
        await self.log(
            f"Atomic add: {'enabled — all or nothing' if self.req.add_atomically else 'disabled — best effort'}",
            "muted"
        )

        # Phase 1: SSH checks
        ssh_results = await self.run_ssh_phase()

        succeeded = sum(1 for r in ssh_results if r.status == "done")
        failed    = sum(1 for r in ssh_results if r.status == "failed")
        await self.log(
            f"Phase 1 complete — {succeeded} succeeded / {failed} failed", "success" if failed == 0 else "warn"
        )

        # Phase 2: Meraki API
        await self.run_api_phase(ssh_results)

        self.status.status = "done"
        await self.send_status()
        await self.log("Bulk onboarding complete ✓", "success")

        return self.status

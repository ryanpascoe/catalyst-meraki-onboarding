# tests/test_meraki_api.py
# Unit tests for MerakiDashboardClient — all HTTP calls are mocked with httpx.

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from meraki_api import MerakiDashboardClient, MerakiAPIError


def make_response(status_code: int, json_body):
    """Create a fake httpx.Response."""
    import json
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.json.return_value = json_body
    response.text = json.dumps(json_body)
    return response


# ------------------------------------------------------------------ #
#  verify_api_key                                                      #
# ------------------------------------------------------------------ #

class TestVerifyApiKey:

    @pytest.mark.asyncio
    async def test_valid_key(self):
        client = MerakiDashboardClient("valid-key")
        mock_resp = make_response(200, {"id": "123456", "name": "Acme Corp"})

        with patch.object(client, "_get", new=AsyncMock(return_value={"id": "123456", "name": "Acme Corp"})):
            ok, name = await client.verify_api_key("123456")

        assert ok is True
        assert name == "Acme Corp"

    @pytest.mark.asyncio
    async def test_invalid_key_401(self):
        client = MerakiDashboardClient("bad-key")
        with patch.object(client, "_get", new=AsyncMock(side_effect=MerakiAPIError(401, "Unauthorized"))):
            ok, name = await client.verify_api_key("123456")

        assert ok is False
        assert "Invalid API key" in name

    @pytest.mark.asyncio
    async def test_org_not_found_404(self):
        client = MerakiDashboardClient("valid-key")
        with patch.object(client, "_get", new=AsyncMock(side_effect=MerakiAPIError(404, "Not found"))):
            ok, name = await client.verify_api_key("999999")

        assert ok is False
        assert "not found" in name.lower()


# ------------------------------------------------------------------ #
#  claim_into_org_inventory                                            #
# ------------------------------------------------------------------ #

class TestClaimIntoOrgInventory:

    @pytest.mark.asyncio
    async def test_claim_single_device(self):
        client = MerakiDashboardClient("valid-key")
        expected = {"serials": ["N_ABCD1234"]}
        with patch.object(client, "_post", new=AsyncMock(return_value=expected)):
            result = await client.claim_into_org_inventory("123456", ["N_ABCD1234"])

        assert result == expected

    @pytest.mark.asyncio
    async def test_claim_multiple_devices(self):
        client = MerakiDashboardClient("valid-key")
        cloud_ids = ["N_AAA111", "N_BBB222", "N_CCC333"]
        expected = {"serials": cloud_ids}
        with patch.object(client, "_post", new=AsyncMock(return_value=expected)) as mock_post:
            result = await client.claim_into_org_inventory("123456", cloud_ids)
            # Verify correct body was sent
            call_body = mock_post.call_args[0][1]
            assert call_body["serials"] == cloud_ids

    @pytest.mark.asyncio
    async def test_claim_rate_limit_429(self):
        client = MerakiDashboardClient("valid-key")
        with patch.object(client, "_post", new=AsyncMock(side_effect=MerakiAPIError(429, "Too Many Requests"))):
            with pytest.raises(MerakiAPIError) as exc_info:
                await client.claim_into_org_inventory("123456", ["N_ABCD1234"])
        assert exc_info.value.status_code == 429


# ------------------------------------------------------------------ #
#  add_devices_to_network                                              #
# ------------------------------------------------------------------ #

class TestAddDevicesToNetwork:

    @pytest.mark.asyncio
    async def test_device_config_mode_payload(self):
        """Device Config → mode should be 'monitored' with credentials."""
        client = MerakiDashboardClient("valid-key")
        devices = [{
            "cloud_id": "N_ABCD1234",
            "mode": "device",
            "username": "admin",
            "password": "Cisco123!",
            "secret": "Enable!",
        }]

        with patch.object(client, "_post", new=AsyncMock(return_value={})) as mock_post:
            await client.add_devices_to_network("L_123", devices)
            body = mock_post.call_args[0][1]

        assert body["serials"] == ["N_ABCD1234"]
        dev_details = body["detailsByDevice"][0]["details"]
        detail_map = {d["name"]: d["value"] for d in dev_details}

        assert detail_map["device mode"] == "monitored"
        assert detail_map["username"] == "admin"
        assert detail_map["password"] == "Cisco123!"
        assert detail_map["enable password"] == "Enable!"

    @pytest.mark.asyncio
    async def test_cloud_config_mode_payload(self):
        """Cloud Config → mode should be 'managed', no credentials in payload."""
        client = MerakiDashboardClient("valid-key")
        devices = [{
            "cloud_id": "N_CLOUD9999",
            "mode": "cloud",
            "username": "admin",
            "password": "Cisco123!",
        }]

        with patch.object(client, "_post", new=AsyncMock(return_value={})) as mock_post:
            await client.add_devices_to_network("L_123", devices)
            body = mock_post.call_args[0][1]

        assert body["serials"] == ["N_CLOUD9999"]
        dev_details = body["detailsByDevice"][0]["details"]
        detail_map = {d["name"]: d["value"] for d in dev_details}

        assert detail_map["device mode"] == "managed"
        # Credentials should NOT be in managed mode payload
        assert "username" not in detail_map
        assert "password" not in detail_map

    @pytest.mark.asyncio
    async def test_add_atomically_flag(self):
        client = MerakiDashboardClient("valid-key")
        devices = [{"cloud_id": "N_ABCD1234", "mode": "device", "username": "a", "password": "b"}]

        with patch.object(client, "_post", new=AsyncMock(return_value={})) as mock_post:
            await client.add_devices_to_network("L_123", devices, add_atomically=True)
            body = mock_post.call_args[0][1]

        assert body["addAtomically"] is True

    @pytest.mark.asyncio
    async def test_mixed_modes_bulk(self):
        """Bulk claim with both device and cloud mode devices."""
        client = MerakiDashboardClient("valid-key")
        devices = [
            {"cloud_id": "N_DEV001", "mode": "device", "username": "admin", "password": "pass"},
            {"cloud_id": "N_CLD002", "mode": "cloud",  "username": "admin", "password": "pass"},
        ]

        with patch.object(client, "_post", new=AsyncMock(return_value={})) as mock_post:
            await client.add_devices_to_network("L_123", devices)
            body = mock_post.call_args[0][1]

        assert set(body["serials"]) == {"N_DEV001", "N_CLD002"}
        by_serial = {d["serial"]: {x["name"]: x["value"] for x in d["details"]}
                     for d in body["detailsByDevice"]}

        assert by_serial["N_DEV001"]["device mode"] == "monitored"
        assert by_serial["N_CLD002"]["device mode"] == "managed"

    @pytest.mark.asyncio
    async def test_device_mode_without_secret(self):
        """Secret is optional for device config mode."""
        client = MerakiDashboardClient("valid-key")
        devices = [{"cloud_id": "N_ABCD1234", "mode": "device", "username": "admin", "password": "pass", "secret": None}]

        with patch.object(client, "_post", new=AsyncMock(return_value={})) as mock_post:
            await client.add_devices_to_network("L_123", devices)
            body = mock_post.call_args[0][1]

        dev_details = body["detailsByDevice"][0]["details"]
        detail_names = [d["name"] for d in dev_details]
        assert "enable password" not in detail_names


# ------------------------------------------------------------------ #
#  full_onboard                                                        #
# ------------------------------------------------------------------ #

class TestFullOnboard:

    @pytest.mark.asyncio
    async def test_successful_full_onboard(self):
        client = MerakiDashboardClient("valid-key")
        devices = [{"cloud_id": "N_ABCD1234", "mode": "device", "username": "admin", "password": "pass"}]

        with patch.object(client, "verify_api_key", new=AsyncMock(return_value=(True, "Acme"))), \
             patch.object(client, "claim_into_org_inventory", new=AsyncMock(return_value={"serials": ["N_ABCD1234"]})), \
             patch.object(client, "add_devices_to_network", new=AsyncMock(return_value={"serials": ["N_ABCD1234"]})), \
             patch("asyncio.sleep", new=AsyncMock()):

            result = await client.full_onboard("123456", "L_123", devices)

        assert result["org_claim"] is not None
        assert result["network_claim"] is not None
        assert result["errors"] == []

    @pytest.mark.asyncio
    async def test_full_onboard_claim_fails(self):
        client = MerakiDashboardClient("valid-key")
        devices = [{"cloud_id": "N_ABCD1234", "mode": "device", "username": "admin", "password": "pass"}]

        with patch.object(client, "claim_into_org_inventory",
                          new=AsyncMock(side_effect=MerakiAPIError(400, "Invalid serial"))), \
             patch("asyncio.sleep", new=AsyncMock()):

            result = await client.full_onboard("123456", "L_123", devices)

        assert len(result["errors"]) > 0
        assert result["network_claim"] is None  # Should not proceed if org claim failed

    @pytest.mark.asyncio
    async def test_full_onboard_network_add_fails(self):
        client = MerakiDashboardClient("valid-key")
        devices = [{"cloud_id": "N_ABCD1234", "mode": "device", "username": "admin", "password": "pass"}]

        with patch.object(client, "claim_into_org_inventory", new=AsyncMock(return_value={"serials": ["N_ABCD1234"]})), \
             patch.object(client, "add_devices_to_network",
                          new=AsyncMock(side_effect=MerakiAPIError(404, "Network not found"))), \
             patch("asyncio.sleep", new=AsyncMock()):

            result = await client.full_onboard("123456", "L_INVALID", devices)

        assert len(result["errors"]) > 0

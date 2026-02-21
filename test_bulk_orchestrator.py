# tests/test_bulk_orchestrator.py
# Unit tests for BulkOrchestrator — SSH and API calls are mocked.

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from bulk_orchestrator import BulkOrchestrator
from models import BulkRequest, DeviceRequest, CheckResult, PrereqChecks
from conftest import make_netmiko_mock


def make_bulk_request(n_device=1, n_cloud=1):
    devices = [
        DeviceRequest(host=f"10.0.0.{i+1}", username="admin", password="pass", mode="device")
        for i in range(n_device)
    ] + [
        DeviceRequest(host=f"10.0.1.{i+1}", username="admin", password="pass", mode="cloud")
        for i in range(n_cloud)
    ]
    return BulkRequest(
        devices=devices,
        meraki_api_key="test-key",
        org_id="123456",
        network_id="L_646829496481105433",
        add_atomically=False,
    )


def make_successful_result(host, mode, cloud_id):
    return CheckResult(
        host=host, mode=mode, status="done",
        cloud_id=cloud_id,
        checks=PrereqChecks(connected=True, ios_ok=True),
    )


def make_failed_result(host, mode):
    return CheckResult(
        host=host, mode=mode, status="failed",
        error="SSH connection failed",
    )


class TestBulkOrchestrator:

    @pytest.mark.asyncio
    async def test_successful_bulk_run(self):
        req = make_bulk_request(n_device=2, n_cloud=1)
        orch = BulkOrchestrator(req)

        mock_results = [
            make_successful_result("10.0.0.1", "device", "N_DEV001"),
            make_successful_result("10.0.0.2", "device", "N_DEV002"),
            make_successful_result("10.0.1.1", "cloud",  "N_CLD001"),
        ]

        with patch("bulk_orchestrator.DeviceChecker") as MockChecker, \
             patch("bulk_orchestrator.MerakiDashboardClient") as MockClient:

            # Each DeviceChecker instance returns the next mock result
            instances = []
            for r in mock_results:
                inst = AsyncMock()
                inst.run.return_value = r
                instances.append(inst)
            MockChecker.side_effect = instances

            api_inst = AsyncMock()
            api_inst.verify_api_key.return_value = (True, "Acme Corp")
            api_inst.full_onboard.return_value = {"org_claim": {}, "network_claim": {}, "errors": []}
            MockClient.return_value = api_inst

            status = await orch.run()

        assert status.status == "done"
        assert status.succeeded == 3
        assert status.failed == 0
        assert status.completed == 3

    @pytest.mark.asyncio
    async def test_partial_failure_proceeds_with_successes(self):
        req = make_bulk_request(n_device=2, n_cloud=0)
        orch = BulkOrchestrator(req)

        results = [
            make_successful_result("10.0.0.1", "device", "N_DEV001"),
            make_failed_result("10.0.0.2", "device"),
        ]

        with patch("bulk_orchestrator.DeviceChecker") as MockChecker, \
             patch("bulk_orchestrator.MerakiDashboardClient") as MockClient:

            instances = []
            for r in results:
                inst = AsyncMock()
                inst.run.return_value = r
                instances.append(inst)
            MockChecker.side_effect = instances

            api_inst = AsyncMock()
            api_inst.verify_api_key.return_value = (True, "Acme")
            api_inst.full_onboard.return_value = {"org_claim": {}, "network_claim": {}, "errors": []}
            MockClient.return_value = api_inst

            status = await orch.run()

        # Should still claim the one that succeeded
        assert status.succeeded == 1
        assert status.failed == 1
        assert api_inst.full_onboard.called, "full_onboard should be called for the 1 successful device"
        # Only the successful device's cloud_id should be passed to API
        call_kwargs = api_inst.full_onboard.call_args.kwargs
        call_devices = call_kwargs["devices"]
        assert len(call_devices) == 1
        assert call_devices[0]["cloud_id"] == "N_DEV001"

    @pytest.mark.asyncio
    async def test_all_fail_skips_api_phase(self):
        req = make_bulk_request(n_device=2, n_cloud=0)
        orch = BulkOrchestrator(req)

        results = [
            make_failed_result("10.0.0.1", "device"),
            make_failed_result("10.0.0.2", "device"),
        ]

        with patch("bulk_orchestrator.DeviceChecker") as MockChecker, \
             patch("bulk_orchestrator.MerakiDashboardClient") as MockClient:

            instances = []
            for r in results:
                inst = AsyncMock()
                inst.run.return_value = r
                instances.append(inst)
            MockChecker.side_effect = instances

            api_inst = AsyncMock()
            MockClient.return_value = api_inst

            status = await orch.run()

        assert status.succeeded == 0
        assert status.failed == 2
        # API should NOT be called if no devices succeeded
        api_inst.full_onboard.assert_not_called()

    @pytest.mark.asyncio
    async def test_correct_credentials_passed_to_api(self):
        """Verify device credentials are passed correctly to the Meraki API phase."""
        req = make_bulk_request(n_device=1, n_cloud=0)
        req.devices[0].username = "netops"
        req.devices[0].password = "Secret789!"
        req.devices[0].secret   = "Enable!"
        orch = BulkOrchestrator(req)

        result = make_successful_result("10.0.0.1", "device", "N_DEV001")

        with patch("bulk_orchestrator.DeviceChecker") as MockChecker, \
             patch("bulk_orchestrator.MerakiDashboardClient") as MockClient:

            inst = AsyncMock()
            inst.run.return_value = result
            MockChecker.return_value = inst

            api_inst = AsyncMock()
            api_inst.verify_api_key.return_value = (True, "Acme")
            api_inst.full_onboard.return_value = {"org_claim": {}, "network_claim": {}, "errors": []}
            MockClient.return_value = api_inst

            await orch.run()

        call_devices = api_inst.full_onboard.call_args.kwargs["devices"]
        assert call_devices[0]["username"] == "netops"
        assert call_devices[0]["password"] == "Secret789!"
        assert call_devices[0]["secret"]   == "Enable!"

    @pytest.mark.asyncio
    async def test_status_updates_during_run(self):
        req = make_bulk_request(n_device=2, n_cloud=0)
        ws = AsyncMock()
        orch = BulkOrchestrator(req, ws=ws)

        results = [
            make_successful_result("10.0.0.1", "device", "N_DEV001"),
            make_successful_result("10.0.0.2", "device", "N_DEV002"),
        ]

        with patch("bulk_orchestrator.DeviceChecker") as MockChecker, \
             patch("bulk_orchestrator.MerakiDashboardClient") as MockClient:

            instances = [AsyncMock(), AsyncMock()]
            instances[0].run.return_value = results[0]
            instances[1].run.return_value = results[1]
            MockChecker.side_effect = instances

            api_inst = AsyncMock()
            api_inst.verify_api_key.return_value = (True, "Acme")
            api_inst.full_onboard.return_value = {"org_claim": {}, "network_claim": {}, "errors": []}
            MockClient.return_value = api_inst

            await orch.run()

        # WebSocket should have received status updates
        calls = [c.args[0] for c in ws.send_json.call_args_list]
        types = [c.get("type") for c in calls]
        assert "bulk_status" in types
        assert "bulk_log" in types

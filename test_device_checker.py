# tests/test_device_checker.py
# Unit tests for DeviceChecker — all SSH calls are mocked.
# Run against real switches using the integration tests instead.

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from device_checker import DeviceChecker, parse_version, MIN_VERSION_DEVICE, MIN_VERSION_CLOUD
from models import DeviceRequest
from conftest import make_netmiko_mock


# ------------------------------------------------------------------ #
#  Version parsing                                                     #
# ------------------------------------------------------------------ #

class TestVersionParsing:
    def test_parse_standard_version(self):
        assert parse_version("17.15.3") == (17, 15, 3)

    def test_parse_version_with_prefix(self):
        assert parse_version("Version 17.12.1a") == (17, 12, 1)

    def test_parse_version_empty(self):
        assert parse_version("") == (0, 0, 0)

    def test_parse_version_no_match(self):
        assert parse_version("no version here") == (0, 0, 0)

    @pytest.mark.parametrize("version,expected", [
        ("17.15.3", True),   # exact minimum
        ("17.16.0", True),   # above minimum
        ("18.0.0",  True),   # major bump
        ("17.15.2", False),  # one patch below
        ("17.14.9", False),  # minor below
        ("16.99.9", False),  # major below
    ])
    def test_device_mode_version_gate(self, version, expected):
        assert (parse_version(version) >= MIN_VERSION_DEVICE) == expected

    @pytest.mark.parametrize("version,expected", [
        ("17.15.0", True),
        ("17.15.3", True),
        ("18.0.0",  True),
        ("17.14.9", False),
        ("16.0.0",  False),
    ])
    def test_cloud_mode_version_gate(self, version, expected):
        assert (parse_version(version) >= MIN_VERSION_CLOUD) == expected


# ------------------------------------------------------------------ #
#  DeviceChecker — Device Config mode                                  #
# ------------------------------------------------------------------ #

class TestDeviceCheckerDeviceMode:

    @pytest.fixture
    def req(self):
        return DeviceRequest(
            host="192.168.1.10", username="admin",
            password="Cisco123!", port=22, mode="device"
        )

    @pytest.mark.asyncio
    async def test_successful_full_run(self, req):
        mock_conn = make_netmiko_mock()
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "done"
        assert result.cloud_id == "N_ABCD1234"
        assert result.checks.connected is True
        assert result.checks.ios_ok is True
        assert result.checks.ios_version == "17.15.3"
        assert result.checks.ntp_configured is True
        assert result.checks.ntp_synced is True
        assert result.checks.dns_configured is True
        assert result.checks.meraki_reachable is True
        assert result.checks.aaa_new_model is True
        assert result.checks.ip_routing is True
        assert result.checks.ip_domain_lookup is True
        assert result.checks.privilege_level == 15

    @pytest.mark.asyncio
    async def test_fails_on_old_ios_version(self, req):
        mock_conn = make_netmiko_mock(ios_version="17.12.1")
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.ios_ok is False
        assert result.checks.ios_version == "17.12.1"
        assert "version" in result.error.lower()

    @pytest.mark.asyncio
    async def test_fails_on_ssh_auth_error(self, req):
        from netmiko import NetmikoAuthenticationException
        with patch("device_checker.ConnectHandler", side_effect=NetmikoAuthenticationException("auth failed")):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.connected is False

    @pytest.mark.asyncio
    async def test_fails_on_ssh_timeout(self, req):
        from netmiko import NetmikoTimeoutException
        with patch("device_checker.ConnectHandler", side_effect=NetmikoTimeoutException("timeout")):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.connected is False

    @pytest.mark.asyncio
    async def test_warns_on_ntp_not_synced(self, req):
        mock_conn = make_netmiko_mock(ntp_synced=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        # NTP sync issue should warn but not hard-fail (tunnel may still work)
        assert result.checks.ntp_synced is False
        assert result.checks.ntp_configured is True

    @pytest.mark.asyncio
    async def test_fails_on_no_aaa(self, req):
        mock_conn = make_netmiko_mock(aaa_ok=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.aaa_new_model is False

    @pytest.mark.asyncio
    async def test_fails_on_no_ip_routing(self, req):
        mock_conn = make_netmiko_mock(ip_routing_ok=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.ip_routing is False

    @pytest.mark.asyncio
    async def test_fails_on_domain_lookup_disabled(self, req):
        mock_conn = make_netmiko_mock(domain_lookup_ok=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.ip_domain_lookup is False

    @pytest.mark.asyncio
    async def test_fails_when_no_cloud_id_returned(self, req):
        mock_conn = make_netmiko_mock(cloud_id=None, tunnel_up=False)

        def send_command_no_id(cmd, **kwargs):
            if "show meraki connect" in cmd:
                return "Tunnel State: Down\nNo Cloud ID assigned yet"
            return make_netmiko_mock().send_command(cmd)

        mock_conn.send_command.side_effect = send_command_no_id

        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            with patch("asyncio.sleep", new_callable=AsyncMock):  # speed up polling
                checker = DeviceChecker(req)
                result = await checker.run()

        assert result.status == "failed"
        assert result.cloud_id is None

    @pytest.mark.asyncio
    async def test_logs_are_populated(self, req):
        mock_conn = make_netmiko_mock()
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert len(result.logs) > 0
        messages = [l.msg for l in result.logs]
        assert any("SSH" in m for m in messages)
        assert any("service meraki connect" in m for m in messages)
        assert any("Cloud ID" in m for m in messages)

    @pytest.mark.asyncio
    async def test_websocket_events_emitted(self, req):
        mock_conn = make_netmiko_mock()
        ws = AsyncMock()
        ws.send_json = AsyncMock()

        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req, ws=ws)
            await checker.run()

        assert ws.send_json.called
        calls = [c.args[0] for c in ws.send_json.call_args_list]
        types = {c.get("type") for c in calls}
        assert "log" in types
        assert "check" in types
        assert "progress" in types


# ------------------------------------------------------------------ #
#  DeviceChecker — Cloud Config mode                                   #
# ------------------------------------------------------------------ #

class TestDeviceCheckerCloudMode:

    @pytest.fixture
    def req(self):
        return DeviceRequest(
            host="192.168.1.20", username="admin",
            password="Cisco123!", port=22, mode="cloud",
        )

    @pytest.mark.asyncio
    async def test_successful_cloud_run(self, req):
        mock_conn = make_netmiko_mock(cloud_id="N_CLOUD9999")
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "done"
        assert result.cloud_id == "N_CLOUD9999"
        assert result.checks.meraki_compatibility is True
        assert result.checks.install_mode is True
        assert result.checks.full_encryption is True
        assert result.checks.http_client_source is True

    @pytest.mark.asyncio
    async def test_fails_on_npe_image(self, req):
        mock_conn = make_netmiko_mock(full_encryption=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.full_encryption is False

    @pytest.mark.asyncio
    async def test_fails_on_bundle_mode(self, req):
        mock_conn = make_netmiko_mock(install_mode=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.install_mode is False

    @pytest.mark.asyncio
    async def test_fails_on_compat_check_fail(self, req):
        mock_conn = make_netmiko_mock(meraki_compat_ok=False)
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.meraki_compatibility is False

    @pytest.mark.asyncio
    async def test_cloud_version_gate_17_14_fails(self, req):
        mock_conn = make_netmiko_mock(ios_version="17.14.1")
        with patch("device_checker.ConnectHandler", return_value=mock_conn):
            checker = DeviceChecker(req)
            result = await checker.run()

        assert result.status == "failed"
        assert result.checks.ios_ok is False

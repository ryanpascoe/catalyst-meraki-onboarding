# conftest.py — shared pytest fixtures for the Meraki onboarding test suite

import sys
import os

# Ensure the project directory is on the path so backend modules
# (models, device_checker, meraki_api, etc.) can be imported from tests.
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from models import DeviceRequest, BulkRequest

# ------------------------------------------------------------------ #
#  Async test support                                                  #
# ------------------------------------------------------------------ #

@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ------------------------------------------------------------------ #
#  Device request fixtures                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def device_request_device_mode():
    """Valid DeviceRequest for Device Configuration mode."""
    return DeviceRequest(
        host="192.168.1.10",
        username="admin",
        password="Cisco123!",
        port=22,
        mode="device",
    )


@pytest.fixture
def device_request_cloud_mode():
    """Valid DeviceRequest for Cloud Configuration mode."""
    return DeviceRequest(
        host="192.168.1.20",
        username="admin",
        password="Cisco123!",
        port=22,
        mode="cloud",
        secret="EnableSecret!",
    )


@pytest.fixture
def bulk_request(device_request_device_mode, device_request_cloud_mode):
    """Valid BulkRequest with two devices."""
    return BulkRequest(
        devices=[device_request_device_mode, device_request_cloud_mode],
        meraki_api_key="test-api-key-abc123",
        org_id="123456",
        network_id="L_646829496481105433",
        add_atomically=False,
    )


# ------------------------------------------------------------------ #
#  Netmiko mock factory                                                #
# ------------------------------------------------------------------ #

def make_netmiko_mock(
    ios_version="17.15.3",
    ntp_synced=True,
    ntp_server="216.239.35.0",
    dns_server="8.8.8.8",
    ping_ok=True,
    aaa_ok=True,
    ip_routing_ok=True,
    domain_lookup_ok=True,
    privilege=15,
    meraki_compat_ok=True,
    install_mode=True,
    full_encryption=True,
    http_client_source=True,
    cloud_id="N_ABCD1234",
    tunnel_up=True,
):
    """
    Returns a MagicMock that behaves like a Netmiko ConnectHandler,
    returning realistic IOS XE CLI output based on parameters.
    """
    mock = MagicMock()

    ntp_status = "Clock is synchronized" if ntp_synced else "Clock is unsynchronized"
    ping_result = "!!" if ping_ok else "....."
    install_str = "Install Mode" if install_mode else "Bundle Mode"
    image_str = "cat9k_iosxe.17.15.3.SPA.bin" if full_encryption else "cat9k_iosxe_npe.17.15.3.SPA.bin"
    http_src = "ip http client source-interface Vlan1" if http_client_source else ""
    compat_str = "Compatible" if meraki_compat_ok else "Incompatible"

    show_meraki_connect = (
        f"Meraki Tunnel Status\n"
        f"  Tunnel State: {'Up' if tunnel_up else 'Down'}\n"
        f"  Cloud ID: {cloud_id}\n"
    )

    def send_command(cmd, **kwargs):
        cmd = cmd.strip()
        if "show version" in cmd and "IOS XE Software" in cmd:
            return f"Cisco IOS XE Software, Version {ios_version}"
        if "show version" in cmd and "Install" in cmd:
            return install_str
        if "show version" in cmd and "System image" in cmd:
            return f"System image file is flash:{image_str}"
        if "show version" in cmd and "Version" in cmd:
            return f"Cisco IOS XE Software, Version {ios_version}"
        if "show ntp status" in cmd:
            return ntp_status
        if "ntp server" in cmd:
            return f"ntp server {ntp_server}" if ntp_server else ""
        if "ip name-server" in cmd:
            return f"ip name-server {dns_server}" if dns_server else ""
        if "ping dashboard.meraki.com" in cmd:
            return f"Sending 2 pings\nSuccess: {ping_result}"
        if "ping registrar.meraki.com" in cmd:
            return f"Sending 2 pings\nSuccess: {ping_result}"
        if "aaa new-model" in cmd:
            return "aaa new-model" if aaa_ok else ""
        if "ip routing" in cmd:
            return "ip routing" if ip_routing_ok else ""
        if "ip domain" in cmd:
            return "" if domain_lookup_ok else "no ip domain lookup"
        if "show privilege" in cmd:
            return f"Current privilege level is {privilege}"
        if "show meraki compatibility" in cmd:
            return f"Compatibility Check  Status\n---\nBoot Mode  INSTALL  - {compat_str}\nSKU  C9300-48U  - {compat_str}"
        if "http client source-interface" in cmd:
            return http_src
        if "show meraki connect" in cmd:
            return show_meraki_connect
        return ""

    mock.send_command.side_effect = send_command
    mock.send_config_set.return_value = ""
    mock.disconnect.return_value = None
    return mock


@pytest.fixture
def netmiko_mock():
    """Default passing Netmiko mock (Device Config mode)."""
    return make_netmiko_mock()


@pytest.fixture
def netmiko_mock_cloud():
    """Default passing Netmiko mock (Cloud Config mode)."""
    return make_netmiko_mock(cloud_id="N_CLOUD9999")


# ------------------------------------------------------------------ #
#  Meraki API mock                                                     #
# ------------------------------------------------------------------ #

@pytest.fixture
def meraki_api_mock():
    """Mock MerakiDashboardClient for API tests."""
    mock = AsyncMock()
    mock.verify_api_key.return_value = (True, "Test Organization")
    mock.claim_into_org_inventory.return_value = {"serials": ["N_ABCD1234"]}
    mock.add_devices_to_network.return_value = {"serials": ["N_ABCD1234"]}
    mock.list_networks.return_value = [
        {"id": "L_646829496481105433", "name": "HQ Network", "productTypes": ["switch"]},
        {"id": "L_999999999999999999", "name": "Branch Network", "productTypes": ["switch"]},
    ]
    mock.full_onboard.return_value = {
        "org_claim": {"serials": ["N_ABCD1234"]},
        "network_claim": {"serials": ["N_ABCD1234"]},
        "errors": [],
    }
    return mock

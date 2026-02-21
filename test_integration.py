# tests/test_integration.py
# Integration tests — connect to REAL switches and REAL Meraki Dashboard API.
#
# SETUP:
#   Copy .env.example to .env and fill in your values, then run:
#     pytest test_integration.py -v -s
#
# WARNING: The cloud config integration test will issue 'service meraki connect'
# on the target switch and claim it to your Meraki org. Only run against
# dedicated test switches.

import pytest
import os
from dotenv import load_dotenv

load_dotenv()

# Read from environment — skip all tests if not configured
SWITCH_HOST_DEVICE    = os.getenv("TEST_SWITCH_HOST_DEVICE")
SWITCH_HOST_CLOUD     = os.getenv("TEST_SWITCH_HOST_CLOUD")
SWITCH_USERNAME       = os.getenv("TEST_SWITCH_USERNAME")
SWITCH_PASSWORD       = os.getenv("TEST_SWITCH_PASSWORD")
SWITCH_SECRET         = os.getenv("TEST_SWITCH_SECRET", "")
MERAKI_API_KEY        = os.getenv("TEST_MERAKI_API_KEY")
MERAKI_ORG_ID         = os.getenv("TEST_MERAKI_ORG_ID")
MERAKI_NETWORK_ID     = os.getenv("TEST_MERAKI_NETWORK_ID")       # optional if name is set
MERAKI_NETWORK_NAME   = os.getenv("TEST_MERAKI_NETWORK_NAME")     # plain-English network name


def resolve_network_id() -> str | None:
    """
    Return a network ID, resolving from name if TEST_MERAKI_NETWORK_ID is not set.
    Calls the Meraki API synchronously at import time so all tests share the result.
    """
    if MERAKI_NETWORK_ID:
        # Guard: if the value doesn't look like a Meraki ID (L_... or N_...) treat it as a name
        if MERAKI_NETWORK_ID.startswith("L_") or MERAKI_NETWORK_ID.startswith("N_"):
            return MERAKI_NETWORK_ID
        else:
            print(f"\n  [.env] WARNING: TEST_MERAKI_NETWORK_ID looks like a name not an ID — treating as TEST_MERAKI_NETWORK_NAME")
            import os; os.environ["TEST_MERAKI_NETWORK_NAME"] = MERAKI_NETWORK_ID
            globals()["MERAKI_NETWORK_NAME"] = MERAKI_NETWORK_ID
    if not (MERAKI_API_KEY and MERAKI_ORG_ID and MERAKI_NETWORK_NAME):
        return None
    import asyncio
    from meraki_api import MerakiDashboardClient
    async def _lookup():
        client = MerakiDashboardClient(MERAKI_API_KEY)
        networks = await client.list_networks(MERAKI_ORG_ID)
        name_lower = MERAKI_NETWORK_NAME.lower()
        for n in networks:
            if n["name"].lower() == name_lower:
                return n["id"]
        # Partial match fallback
        for n in networks:
            if name_lower in n["name"].lower():
                print(f"\n  [.env] Partial match: '{n['name']}' → {n['id']}")
                return n["id"]
        available = ", ".join(f"'{n['name']}'" for n in networks)
        raise ValueError(
            f"Network '{MERAKI_NETWORK_NAME}' not found in org {MERAKI_ORG_ID}.\n"
            f"  Available networks: {available}"
        )
    return asyncio.run(_lookup())


RESOLVED_NETWORK_ID   = resolve_network_id()

SWITCH_AVAILABLE      = bool(SWITCH_HOST_DEVICE and SWITCH_USERNAME and SWITCH_PASSWORD)
MERAKI_API_AVAILABLE  = bool(MERAKI_API_KEY and MERAKI_ORG_ID and RESOLVED_NETWORK_ID)

skip_no_switch  = pytest.mark.skipif(not SWITCH_AVAILABLE,     reason="No real switch configured in .env")
skip_no_api     = pytest.mark.skipif(not MERAKI_API_AVAILABLE, reason="No Meraki API credentials in .env")
skip_no_both    = pytest.mark.skipif(not (SWITCH_AVAILABLE and MERAKI_API_AVAILABLE), reason="Need both switch and API")


# ------------------------------------------------------------------ #
#  SSH / Device checks                                                 #
# ------------------------------------------------------------------ #

class TestRealSwitchChecks:

    @skip_no_switch
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_ssh_connection(self):
        """Verify we can SSH into the test switch."""
        from models import DeviceRequest
        from device_checker import DeviceChecker

        req = DeviceRequest(
            host=SWITCH_HOST_DEVICE,
            username=SWITCH_USERNAME,
            password=SWITCH_PASSWORD,
            secret=SWITCH_SECRET or None,
            mode="device",
        )
        checker = DeviceChecker(req)
        result = await checker.check_ssh()
        assert result is True, "SSH connection to real switch failed"
        if checker.conn:
            checker.conn.disconnect()

    @skip_no_switch
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_ios_version_check(self):
        """Verify IOS XE version is readable and meets minimum."""
        from models import DeviceRequest
        from device_checker import DeviceChecker

        req = DeviceRequest(
            host=SWITCH_HOST_DEVICE,
            username=SWITCH_USERNAME,
            password=SWITCH_PASSWORD,
            secret=SWITCH_SECRET or None,
            mode="device",
        )
        checker = DeviceChecker(req)
        await checker.check_ssh()
        result = await checker.check_ios_version()

        print(f"\n  IOS XE version: {checker.result.checks.ios_version}")
        print(f"  Meets minimum:  {checker.result.checks.ios_ok}")

        assert checker.result.checks.ios_version is not None, "Could not parse IOS XE version"
        if checker.conn:
            checker.conn.disconnect()

    @skip_no_switch
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_ntp_check(self):
        """Check NTP configuration on real switch."""
        from models import DeviceRequest
        from device_checker import DeviceChecker

        req = DeviceRequest(
            host=SWITCH_HOST_DEVICE,
            username=SWITCH_USERNAME,
            password=SWITCH_PASSWORD,
            secret=SWITCH_SECRET or None,
            mode="device",
        )
        checker = DeviceChecker(req)
        await checker.check_ssh()
        await checker.check_ntp()

        print(f"\n  NTP configured: {checker.result.checks.ntp_configured}")
        print(f"  NTP synced:     {checker.result.checks.ntp_synced}")

        assert checker.result.checks.ntp_configured is not None
        if checker.conn:
            checker.conn.disconnect()

    @skip_no_switch
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_dns_check(self):
        """Check DNS configuration and Meraki reachability on real switch."""
        from models import DeviceRequest
        from device_checker import DeviceChecker

        req = DeviceRequest(
            host=SWITCH_HOST_DEVICE,
            username=SWITCH_USERNAME,
            password=SWITCH_PASSWORD,
            secret=SWITCH_SECRET or None,
            mode="device",
        )
        checker = DeviceChecker(req)
        await checker.check_ssh()
        await checker.check_dns()

        print(f"\n  DNS configured:  {checker.result.checks.dns_configured}")
        print(f"  Meraki resolves: {checker.result.checks.dns_resolvable}")

        assert checker.result.checks.dns_configured is not None
        if checker.conn:
            checker.conn.disconnect()

    @skip_no_switch
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_full_prereq_check_device_mode(self):
        """
        Full prerequisite check on a real switch in Device Config mode.
        Does NOT issue 'service meraki connect'.
        """
        from models import DeviceRequest
        from device_checker import DeviceChecker

        req = DeviceRequest(
            host=SWITCH_HOST_DEVICE,
            username=SWITCH_USERNAME,
            password=SWITCH_PASSWORD,
            secret=SWITCH_SECRET or None,
            mode="device",
        )

        # Patch run_service_meraki_connect to stop before actually connecting
        from unittest.mock import AsyncMock, patch
        with patch.object(DeviceChecker, "run_service_meraki_connect", new=AsyncMock(return_value=None)):
            checker = DeviceChecker(req)
            result = await checker.run()

        print("\n  Check results:")
        print(f"    SSH:            {result.checks.connected}")
        print(f"    IOS XE:         {result.checks.ios_version} (ok={result.checks.ios_ok})")
        print(f"    NTP configured: {result.checks.ntp_configured}")
        print(f"    NTP synced:     {result.checks.ntp_synced}")
        print(f"    DNS configured: {result.checks.dns_configured}")
        print(f"    Meraki reach:   {result.checks.meraki_reachable}")
        print(f"    aaa new-model:  {result.checks.aaa_new_model}")
        print(f"    ip routing:     {result.checks.ip_routing}")
        print(f"    domain lookup:  {result.checks.ip_domain_lookup}")
        print(f"    Privilege lvl:  {result.checks.privilege_level}")
        print(f"\n  Status: {result.status}")

        assert result.checks.connected is True
        assert result.checks.ios_version is not None


# ------------------------------------------------------------------ #
#  Full end-to-end (SSH + service meraki connect + Meraki API)        #
# WARNING: This claims the switch to your Meraki org!                 #
# ------------------------------------------------------------------ #

class TestRealEndToEnd:

    @skip_no_both
    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_full_device_config_onboard(self):
        """
        FULL END-TO-END: SSH checks + service meraki connect + Meraki API claim.
        Run against a dedicated test switch — this WILL claim it to your Meraki org.
        """
        from models import BulkRequest, DeviceRequest
        from bulk_orchestrator import BulkOrchestrator

        req = BulkRequest(
            devices=[DeviceRequest(
                host=SWITCH_HOST_DEVICE,
                username=SWITCH_USERNAME,
                password=SWITCH_PASSWORD,
                secret=SWITCH_SECRET or None,
                mode="device",
            )],
            meraki_api_key=MERAKI_API_KEY,
            org_id=MERAKI_ORG_ID,
            network_id=RESOLVED_NETWORK_ID,
            add_atomically=False,
        )

        orch = BulkOrchestrator(req)
        status = await orch.run()

        print(f"\n  Succeeded: {status.succeeded}")
        print(f"  Failed:    {status.failed}")
        if status.results:
            r = status.results[0]
            print(f"  Cloud ID:  {r.cloud_id}")
            print(f"  Status:    {r.status}")

        assert status.succeeded >= 1
        r = status.results[0]
        assert r.cloud_id is not None

        # Step 6 validation — confirm operating mode in Dashboard matches what was requested
        print(f"\n  Validating operating mode in Dashboard for Cloud ID: {r.cloud_id}…")
        from meraki_api import MerakiDashboardClient
        client = MerakiDashboardClient(MERAKI_API_KEY)

        # ── Diagnostic: dump raw network devices list ──────────────────
        print(f"\n  [diag] Fetching GET /networks/{RESOLVED_NETWORK_ID}/devices…")
        try:
            raw_devices = await client.get_network_devices(RESOLVED_NETWORK_ID)
            print(f"  [diag] {len(raw_devices)} device(s) in network:")
            for d in raw_devices:
                details = {x['name']: x['value'] for x in d.get('details', []) if 'name' in x}
                print(f"    serial={d.get('serial')}  model={d.get('model')}  details={details}")
        except Exception as e:
            print(f"  [diag] ERROR fetching network devices: {e}")

        # ── Diagnostic: dump org inventory for this Cloud ID ───────────
        print(f"\n  [diag] Fetching org inventory for serial {r.cloud_id}…")
        try:
            inv = await client.get_inventory_device(MERAKI_ORG_ID, r.cloud_id)
            print(f"  [diag] Inventory entry: {inv}")
        except Exception as e:
            print(f"  [diag] ERROR fetching inventory: {e}")
        # ── End diagnostic ─────────────────────────────────────────────

        expected_mode = "monitored" if r.mode == "device" else "managed"
        import asyncio
        max_attempts = 8
        for attempt in range(max_attempts):
            match, actual = await client.verify_device_mode(r.cloud_id, MERAKI_ORG_ID, expected_mode)
            print(f"  Attempt {attempt + 1}/{max_attempts} — Dashboard reports: '{actual}'")
            if match:
                break
            await asyncio.sleep(15)

        print(f"  Expected mode : {expected_mode}")
        print(f"  Actual mode   : {actual}")
        print(f"  Mode match    : {'✓ PASS' if match else '✗ FAIL'}")
        assert match, (
            f"Device mode mismatch — expected '{expected_mode}', "
            f"Dashboard returned '{actual}'. "
            f"Check the device in Dashboard under Catalyst Cloud Networking → Switches."
        )


# ------------------------------------------------------------------ #
#  Meraki API — real API calls (no switch needed)                     #
# ------------------------------------------------------------------ #

class TestRealMerakiAPI:

    @skip_no_api
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_verify_api_key(self):
        """Verify the API key and org ID are valid."""
        from meraki_api import MerakiDashboardClient

        client = MerakiDashboardClient(MERAKI_API_KEY)
        ok, name = await client.verify_api_key(MERAKI_ORG_ID)

        print(f"\n  API Key valid: {ok}")
        print(f"  Org name:      {name}")

        assert ok is True, f"API key verification failed: {name}"

    @skip_no_api
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_list_networks(self):
        """List networks in the org — useful for finding the right network_id."""
        from meraki_api import MerakiDashboardClient

        client = MerakiDashboardClient(MERAKI_API_KEY)
        networks = await client.list_networks(MERAKI_ORG_ID)

        print(f"\n  Networks in org {MERAKI_ORG_ID}:")
        for n in networks:
            print(f"    {n['id']}  {n['name']}")

        assert isinstance(networks, list)
        assert len(networks) > 0

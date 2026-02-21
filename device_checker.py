"""
device_checker.py — SSH-based prerequisite checker using Netmiko.
Handles all show command parsing and issues 'service meraki connect'.
"""

import asyncio
import re
import logging
from datetime import datetime
from typing import Optional

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from models import DeviceRequest, CheckResult, PrereqChecks, LogEntry

logger = logging.getLogger(__name__)

MIN_VERSION_DEVICE = (17, 15, 3)
MIN_VERSION_CLOUD  = (17, 15, 0)

COLORS = {
    "info":    "#e0eeff",
    "success": "#00e676",
    "warn":    "#ffd600",
    "error":   "#ff4444",
    "accent":  "#00c8ff",
    "muted":   "#4a6080",
}


def parse_version(v: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


class DeviceChecker:
    def __init__(self, req: DeviceRequest, ws=None):
        self.req    = req
        self.ws     = ws
        self.result = CheckResult(host=req.host, mode=req.mode, status="checking")
        self.conn   = None

    async def log(self, msg: str, color: str = "info"):
        entry = LogEntry(time=now(), msg=msg, color=COLORS.get(color, color))
        self.result.logs.append(entry)
        logger.info("[%s] %s", self.req.host, msg)
        if self.ws:
            await self.ws.send_json({"type": "log", "msg": msg, "color": entry.color})

    async def send_check(self, key: str, value):
        if self.ws:
            await self.ws.send_json({"type": "check", "key": key, "value": value})

    async def send_progress(self, pct: int):
        if self.ws:
            await self.ws.send_json({"type": "progress", "pct": pct})

    async def fail(self, reason: str):
        self.result.status = "failed"
        self.result.error  = reason
        await self.log(f"✗ FAILED: {reason}", "error")
        await self.send_progress(100)

    def _connect(self):
        return ConnectHandler(
            device_type="cisco_ios",
            host=self.req.host,
            username=self.req.username,
            password=self.req.password,
            port=self.req.port,
            secret=self.req.secret or self.req.password,
            timeout=30,
            auth_timeout=20,
            fast_cli=False,
        )

    def _send_command(self, cmd: str) -> str:
        return self.conn.send_command(cmd, read_timeout=30)

    def _send_config(self, cmds: list[str]) -> str:
        return self.conn.send_config_set(cmds, read_timeout=60)

    async def run_command(self, cmd: str) -> str:
        return await asyncio.get_event_loop().run_in_executor(None, self._send_command, cmd)

    async def run_config(self, cmds: list[str]) -> str:
        return await asyncio.get_event_loop().run_in_executor(None, self._send_config, cmds)

    # ------------------------------------------------------------------ #
    #  Checks                                                              #
    # ------------------------------------------------------------------ #

    async def check_ssh(self) -> bool:
        await self.log(f"Initiating SSH to {self.req.host}:{self.req.port}…", "accent")
        try:
            self.conn = await asyncio.get_event_loop().run_in_executor(None, self._connect)
            self.result.checks.connected = True
            await self.send_check("connected", True)
            await self.log(f"SSH session established as '{self.req.username}'", "success")
            return True
        except NetmikoAuthenticationException:
            self.result.checks.connected = False
            await self.send_check("connected", False)
            await self.log("SSH authentication failed — check credentials and privilege level", "error")
            return False
        except NetmikoTimeoutException:
            self.result.checks.connected = False
            await self.send_check("connected", False)
            await self.log(f"SSH connection timed out to {self.req.host}:{self.req.port}", "error")
            return False
        except Exception as e:
            self.result.checks.connected = False
            await self.send_check("connected", False)
            await self.log(f"SSH error: {e}", "error")
            return False

    async def check_ios_version(self) -> bool:
        await self.log("Running: show version | include IOS XE Software", "muted")
        out = await self.run_command("show version | include IOS XE Software")
        match = re.search(r"Version\s+([\d.]+)", out)
        if not match:
            out2 = await self.run_command("show version | include Version")
            match = re.search(r"Version\s+([\d.]+)", out2)

        if not match:
            self.result.checks.ios_ok = False
            await self.log("Could not parse IOS XE version", "error")
            return False

        version_str = match.group(1)
        version_tuple = parse_version(version_str)
        minimum = MIN_VERSION_DEVICE if self.req.mode == "device" else MIN_VERSION_CLOUD
        min_str = ".".join(str(x) for x in minimum)
        ok = version_tuple >= minimum

        self.result.checks.ios_version = version_str
        self.result.checks.ios_ok = ok
        await self.send_check("iosVersion", version_str)
        await self.send_check("iosOk", ok)
        mode_label = "Cloud Config" if self.req.mode == "cloud" else "Device Config"

        if ok:
            await self.log(f"IOS XE {version_str} — ✓ Meets minimum {min_str}+ for {mode_label} mode", "success")
        else:
            await self.log(f"IOS XE {version_str} — ✗ Below required minimum {min_str}. Upgrade required.", "error")
        return ok

    async def check_ntp(self) -> bool:
        await self.log("Running: show ntp status", "muted")
        out = await self.run_command("show ntp status")
        synced = "synchronized" in out.lower() and "unsynchronized" not in out.lower()

        await self.log("Running: show running-config | include ntp server", "muted")
        cfg = await self.run_command("show running-config | include ntp server")
        configured = bool(re.search(r"ntp server\s+\S+", cfg))

        self.result.checks.ntp_configured = configured
        self.result.checks.ntp_synced = synced
        await self.send_check("ntpConfigured", configured)
        await self.send_check("ntpSynced", synced)

        srv_match = re.search(r"ntp server\s+(\S+)", cfg)
        srv = srv_match.group(1) if srv_match else "unknown"

        if not configured:
            await self.log("✗ No NTP server configured — add 'ntp server <ip>'", "error")
            return False
        if not synced:
            await self.log(f"NTP server {srv} configured but NOT synchronized — check reachability", "warn")
            return False

        await self.log(f"NTP server {srv} configured — clock synchronized ✓", "success")
        return True

    async def check_dns(self) -> bool:
        await self.log("Running: show running-config | include ip name-server", "muted")
        cfg = await self.run_command("show running-config | include ip name-server")
        configured = bool(re.search(r"ip name-server\s+\S+", cfg))

        self.result.checks.dns_configured = configured
        await self.send_check("dnsConfigured", configured)

        if not configured:
            await self.log("✗ No DNS name-server configured — add 'ip name-server <ip>'", "error")
            return False

        srv_match = re.search(r"ip name-server\s+(\S+)", cfg)
        srv = srv_match.group(1) if srv_match else "configured"
        await self.log(f"ip name-server {srv} configured ✓", "success")

        await self.log("Running: ping dashboard.meraki.com repeat 2", "muted")
        ping = await self.run_command("ping dashboard.meraki.com repeat 2")
        resolvable = "!!" in ping or bool(re.search(r"\d+\.\d+\.\d+\.\d+", ping))

        self.result.checks.dns_resolvable = resolvable
        await self.send_check("dnsResolvable", resolvable)

        if resolvable:
            await self.log("dashboard.meraki.com resolves ✓", "success")
        else:
            await self.log("✗ dashboard.meraki.com did not resolve — check DNS + internet path", "error")
        return configured

    async def check_meraki_reachability(self) -> bool:
        await self.log("Pinging dashboard.meraki.com…", "muted")
        ping = await self.run_command("ping dashboard.meraki.com repeat 2")
        reachable = "!!" in ping or bool(re.search(r"\d+\.\d+\.\d+\.\d+", ping))

        self.result.checks.meraki_reachable = reachable
        await self.send_check("merakiReachable", reachable)

        if reachable:
            await self.log("dashboard.meraki.com reachable ✓", "success")
        else:
            await self.log("✗ Cannot ping dashboard.meraki.com — check internet path", "warn")
        return reachable

    async def check_device_config_prereqs(self) -> bool:
        await self.log("── Device Configuration Mode checks ──", "accent")
        all_ok = True

        # aaa new-model
        out = await self.run_command("show running-config | include aaa new-model")
        ok = "aaa new-model" in out
        self.result.checks.aaa_new_model = ok
        await self.send_check("aaaNewModel", ok)
        if ok:
            await self.log("aaa new-model ✓", "success")
        else:
            await self.log("✗ aaa new-model not configured — required for Device Config mode", "error")
            all_ok = False

        # ip routing
        out = await self.run_command("show running-config | include ^ip routing")
        ok = "ip routing" in out
        self.result.checks.ip_routing = ok
        await self.send_check("ipRouting", ok)
        if ok:
            await self.log("ip routing enabled ✓", "success")
        else:
            await self.log("✗ ip routing not enabled — add 'ip routing' to global config", "error")
            all_ok = False

        # ip domain lookup
        out = await self.run_command("show running-config | include ip domain")
        ok = "no ip domain lookup" not in out
        self.result.checks.ip_domain_lookup = ok
        await self.send_check("domainLookup", ok)
        if ok:
            await self.log("ip domain lookup enabled ✓", "success")
        else:
            await self.log("✗ 'no ip domain lookup' present — remove it to allow hostname resolution", "error")
            all_ok = False

        # privilege level
        out = await self.run_command("show privilege")
        priv_match = re.search(r"Current privilege level is (\d+)", out)
        if priv_match:
            priv = int(priv_match.group(1))
            self.result.checks.privilege_level = priv
            if priv == 15:
                await self.log(f"Privilege level: {priv} ✓", "success")
            else:
                await self.log(f"✗ Privilege level is {priv} — privilege-15 required", "error")
                all_ok = False

        return all_ok

    async def check_cloud_config_prereqs(self) -> bool:
        await self.log("── Cloud Configuration Mode checks ──", "accent")
        all_ok = True

        # show meraki compatibility
        await self.log("Running: show meraki compatibility", "accent")
        out = await self.run_command("show meraki compatibility")
        ok = "compatible" in out.lower() and "incompatible" not in out.lower()
        self.result.checks.meraki_compatibility = ok
        await self.send_check("compatibilityCheck", ok)
        if ok:
            await self.log("show meraki compatibility: passed ✓", "success")
        else:
            await self.log("✗ Meraki compatibility check failed — review supported model list", "error")
            all_ok = False

        # Install mode — use 'show boot' as primary source, which explicitly states
        # the current boot mode on IOS XE 16.x+. Fall back to parsing the Mode column
        # in 'show version' (case-sensitive match on INSTALL/BUNDLE).
        await self.log("Running: show boot", "accent")
        boot_out = await self.run_command("show boot")
        install_mode = False

        # 'show boot' on IOS XE prints lines like:
        #   Current Boot Mode : install
        #   Boot Mode         : install
        boot_mode_match = re.search(r"(?:current\s+)?boot\s+mode\s*[:\-]\s*(\S+)", boot_out, re.IGNORECASE)
        if boot_mode_match:
            detected = boot_mode_match.group(1).strip().lower()
            install_mode = detected == "install"
            await self.log(f"Boot mode (show boot): {detected.upper()}", "accent")
        else:
            # Fallback: 'show version' table has a Mode column — the column header is
            # 'Mode' (capital M) so we need case-insensitive include via grep logic.
            # Fetch the full show version and scan for INSTALL or BUNDLE in context.
            await self.log("'show boot' mode field not found — checking show version", "accent")
            ver_out = await self.run_command("show version")
            # Look for lines containing INSTALL or BUNDLE as standalone words
            install_match = re.search(r'\bINSTALL\b', ver_out)
            bundle_match  = re.search(r'\bBUNDLE\b',  ver_out)
            # Also check packages.conf in BOOT variable — install mode uses packages.conf
            packages_conf = "packages.conf" in ver_out.lower()
            if install_match or packages_conf:
                install_mode = True
                await self.log("Boot mode (show version): INSTALL", "accent")
            elif bundle_match:
                install_mode = False
                await self.log("Boot mode (show version): BUNDLE", "accent")
            else:
                await self.log("⚠ Could not determine boot mode — assuming BUNDLE", "warn")
                install_mode = False

        self.result.checks.install_mode = install_mode
        await self.send_check("installMode", install_mode)
        if install_mode:
            await self.log("Boot mode: INSTALL ✓", "success")
        else:
            await self.log("✗ BUNDLE mode detected — convert to INSTALL mode before cloud migration", "error")
            all_ok = False

        # Full encryption (non-NPE)
        out = await self.run_command("show version | include System image")
        npe = "npe" in out.lower()
        ok = not npe
        self.result.checks.full_encryption = ok
        await self.send_check("fullEncryption", ok)
        if ok:
            await self.log("Full encryption IOS-XE image (non-NPE) ✓", "success")
        else:
            await self.log("✗ NPE image detected — full encryption image required for Cloud Config migration", "error")
            all_ok = False

        # http client source-interface
        out = await self.run_command("show running-config | include http client source-interface")
        ok = "source-interface" in out
        self.result.checks.http_client_source = ok
        await self.send_check("httpClientSource", ok)
        if ok:
            iface = out.strip().split()[-1]
            await self.log(f"ip http client source-interface {iface} ✓", "success")
        else:
            await self.log("⚠  ip http client source-interface not set — configure to internet-facing VLAN SVI", "warn")

        return all_ok

    async def run_service_meraki_connect(self, cloud_id_only: bool = False) -> Optional[str]:
        await self.log("─" * 44, "muted")
        await self.log("Running: configure terminal", "accent")
        await self.log("Running: service meraki connect", "accent")

        try:
            await self.run_config(["service meraki connect"])
        except Exception as e:
            await self.log(f"Error issuing service meraki connect: {e}", "error")
            return None

        if cloud_id_only:
            await self.log("Polling for Cloud ID…", "warn")
        else:
            await self.log("Meraki service started — polling for Cloud ID and tunnel state…", "warn")

        cloud_id = None
        for attempt in range(18):
            # First attempt: check immediately — Cloud ID is often already present
            if attempt > 0:
                await asyncio.sleep(10)
            await self.log(f"show meraki connect (attempt {attempt + 1}/18)…", "muted")
            out = await self.run_command("show meraki connect")

            id_match = re.search(
                r"(?:Cloud[\s_]?ID|Meraki[\s_]?ID|Device[\s_]?ID)\s*[:\-]\s*([A-Za-z0-9_\-]+)",
                out, re.IGNORECASE
            )

            if id_match:
                cloud_id = id_match.group(1).strip()
                await self.log(f"Cloud ID: {cloud_id}", "success")
                await self.send_check("cloudId", cloud_id)
                # Readiness check mode: Cloud ID is all we need — return immediately
                if cloud_id_only:
                    return cloud_id
                break

            tunnel_up = re.search(r"tunnel\s*(?:state|status)\s*[:\-]?\s*up", out, re.IGNORECASE)
            if tunnel_up:
                await self.log("Meraki Tunnel State: Up ✓", "success")
                break

            if attempt == 5:
                await self.log("Still waiting — check firewall if stalled (TCP/443 to *.meraki.com)", "warn")

        if not cloud_id:
            await self.log("✗ Could not obtain Cloud ID — run 'show meraki connect' manually", "error")

        return cloud_id

    # ------------------------------------------------------------------ #
    #  Main                                                                #
    # ------------------------------------------------------------------ #

    async def issue_service_meraki_connect(self) -> Optional[str]:
        """
        Public method for semi-auto mode: SSH in and issue service meraki connect,
        returning the Cloud ID. Does not run prerequisite checks.
        """
        connected = await self.check_ssh()
        if not connected:
            raise RuntimeError(f"SSH connection failed to {self.req.host}")
        return await self.run_service_meraki_connect(cloud_id_only=True)

    async def run(self) -> CheckResult:
        self.result.status = "checking"
        try:
            if not await self.check_ssh():
                await self.fail("SSH connection failed")
                return self.result
            await self.send_progress(10)

            if not await self.check_ios_version():
                await self.fail("IOS XE version below minimum requirement")
                self.conn.disconnect()
                return self.result
            await self.send_progress(22)

            ntp_ok = await self.check_ntp()
            await self.send_progress(34)
            if not ntp_ok:
                await self.log("NTP issue — tunnel may fail without clock sync", "warn")

            await self.check_dns()
            await self.send_progress(44)

            await self.check_meraki_reachability()
            await self.send_progress(54)

            if self.req.mode == "cloud":
                mode_ok = await self.check_cloud_config_prereqs()
            else:
                mode_ok = await self.check_device_config_prereqs()
            await self.send_progress(70)

            if not mode_ok:
                await self.fail("Mode-specific prerequisites failed — resolve before onboarding")
                self.conn.disconnect()
                return self.result

            # Readiness check mode: stop here, don't issue service meraki connect
            if self.req.skip_connect:
                self.result.status = "ready"
                await self.send_progress(100)
                await self.log("── All prerequisites passed. Device is ready for Meraki onboarding. ──", "success")
                self.conn.disconnect()
                return self.result

            self.result.status = "onboarding"
            cloud_id = await self.run_service_meraki_connect()
            await self.send_progress(88)

            if cloud_id:
                self.result.cloud_id = cloud_id
                await self.send_check("cloudId", cloud_id)
                self.result.status = "done"
                await self.log(f"✓ Cloud ID ready: {cloud_id} — handing off to Meraki Dashboard API", "success")
            else:
                await self.fail("Failed to obtain Cloud ID")

        except Exception as e:
            logger.exception("Unexpected error: %s", e)
            await self.fail(f"Unexpected error: {e}")
        finally:
            if self.conn:
                try:
                    self.conn.disconnect()
                except Exception:
                    pass
            await self.send_progress(100)

        return self.result

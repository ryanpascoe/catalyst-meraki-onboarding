"""
config_analyzer.py — IOS XE running-config compatibility analyser.

Pulls 'show running-config' via an existing SSH session (or opens its own),
then classifies every detected feature against the Meraki Cloud Configuration
Mode support matrix.

Result categories:
  TRANSLATABLE  — Meraki Dashboard equivalent exists AND can be auto-pushed
                  via the Dashboard API (merakicat can translate these).
  SUPPORTED     — Feature exists in Dashboard but must be configured manually
                  after migration.
  PARTIAL       — Feature exists but with significant limitations vs IOS XE.
  NOT_SUPPORTED — No equivalent in Meraki Cloud Configuration mode.

Each feature entry carries:
  key           str   — unique identifier
  category      str   — switch | port | security | qos | management | routing
  name          str   — human-readable feature name
  status        str   — TRANSLATABLE | SUPPORTED | PARTIAL | NOT_SUPPORTED
  detected      bool  — whether the feature was found in the running config
  detected_val  str   — short excerpt of what was found (e.g. hostname value)
  guidance      str   — what to do post-migration in Dashboard
"""

import re
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler

logger = logging.getLogger(__name__)


# ── Status constants ──────────────────────────────────────────────────────────
TRANSLATABLE  = "TRANSLATABLE"
SUPPORTED     = "SUPPORTED"
PARTIAL       = "PARTIAL"
NOT_SUPPORTED = "NOT_SUPPORTED"


@dataclass
class FeatureResult:
    key:          str
    category:     str
    name:         str
    status:       str           # TRANSLATABLE / SUPPORTED / PARTIAL / NOT_SUPPORTED
    detected:     bool = False
    detected_val: str  = ""
    guidance:     str  = ""


@dataclass
class AnalysisResult:
    host:          str
    features:      list = field(default_factory=list)
    error:         str  = ""
    # summary counts (populated after analysis)
    n_translatable:  int = 0
    n_supported:     int = 0
    n_partial:       int = 0
    n_not_supported: int = 0
    n_detected:      int = 0
    # static checks from config text (offline mode only)
    static_checks: Optional[dict] = None


# ── Feature encyclopedia ──────────────────────────────────────────────────────
# Each entry is a dict describing one IOS XE feature and its Meraki equivalent.
# The 'detect' key is a callable that receives the full running-config string
# and returns (detected: bool, detected_val: str).

def _find(pattern: str, cfg: str, flags=re.IGNORECASE | re.MULTILINE):
    """
    Find pattern in config and return (True, matched_line) or (False, None)
    """
    m = re.search(pattern, cfg, flags)
    if not m:
        return False, None
    
    # Extract the actual matched line correctly
    matched_text = m.group(0).strip()
    
    # If we need the full line containing the match:
    lines = cfg.splitlines()
    match_start_char = m.start(0)
    
    # Find which line number contains this character position
    char_count = 0
    for line in lines:
        line_length = len(line) + 1  # +1 for newline character
        if char_count <= match_start_char < char_count + line_length:
            return True, line.strip()
        char_count += line_length
    
    # Fallback: return the matched text itself
    return True, matched_text
def _find_all(pattern: str, cfg: str) -> tuple[bool, str]:
    """Return (True, 'N matches') or (False, '')."""
    matches = re.findall(pattern, cfg, re.MULTILINE)
    if matches:
        return True, f"{len(matches)} instance(s)"
    return False, ""


FEATURE_ENCYCLOPEDIA = [

    # ── Switch-level ─────────────────────────────────────────────────────────
    {
        "key": "hostname",
        "category": "switch",
        "name": "Hostname",
        "status": TRANSLATABLE,
        "guidance": "Automatically applied to the Meraki device name in Dashboard.",
        "detect": lambda cfg: _find(r"^hostname\s+(\S+)", cfg),
    },
    {
        "key": "stp_mode_rstp",
        "category": "switch",
        "name": "Spanning Tree — RSTP (rapid-pvst)",
        "status": TRANSLATABLE,
        "guidance": "Meraki Cloud Config supports RSTP. Mode is applied automatically.",
        "detect": lambda cfg: _find(r"^spanning-tree mode rapid-pvst", cfg),
    },
    {
        "key": "stp_mode_pvst",
        "category": "switch",
        "name": "Spanning Tree — PVST",
        "status": PARTIAL,
        "guidance": "Meraki uses RSTP. PVST-specific per-VLAN timers are not carried over — verify STP topology post-migration.",
        "detect": lambda cfg: _find(r"^spanning-tree mode pvst", cfg),
    },
    {
        "key": "stp_mode_mst",
        "category": "switch",
        "name": "Spanning Tree — MST",
        "status": NOT_SUPPORTED,
        "guidance": "MST is not supported in Meraki Cloud Configuration mode. Review STP design before migrating.",
        "detect": lambda cfg: _find(r"^spanning-tree mode mst", cfg),
    },
    {
        "key": "stp_portfast_default",
        "category": "switch",
        "name": "STP Portfast Default (global)",
        "status": SUPPORTED,
        "guidance": "Configure PortFast per-port in Dashboard: Switch → Ports → Port Settings.",
        "detect": lambda cfg: _find(r"^spanning-tree portfast default", cfg),
    },
    {
        "key": "vtp",
        "category": "switch",
        "name": "VTP (VLAN Trunking Protocol)",
        "status": NOT_SUPPORTED,
        "guidance": "Meraki does not use VTP. VLANs are managed centrally in Dashboard. Define VLANs manually in Networks → VLANs.",
        "detect": lambda cfg: _find(r"^vtp\s+(mode|domain|password|version)", cfg),
    },
    {
        "key": "stack",
        "category": "switch",
        "name": "Switch Stack (StackWise)",
        "status": TRANSLATABLE,
        "guidance": "Meraki supports stacking. Stack members are discovered automatically. Verify stack membership in Dashboard.",
        "detect": lambda cfg: _find(r"^(switch\s+\d+\s+provision|stack-mac)", cfg),
    },
    {
        "key": "udld",
        "category": "switch",
        "name": "UDLD",
        "status": NOT_SUPPORTED,
        "guidance": "UDLD is not available in Meraki Cloud Configuration mode. Consider Meraki's built-in STP Loop Guard as an alternative.",
        "detect": lambda cfg: _find(r"^udld\s+(enable|aggressive)", cfg),
    },

    # ── Routing ───────────────────────────────────────────────────────────────
    {
        "key": "static_routes",
        "category": "routing",
        "name": "Static Routes (ip route)",
        "status": TRANSLATABLE,
        "guidance": "Static routes are translatable via the Dashboard API. Verify next-hop reachability post-migration.",
        "detect": lambda cfg: _find_all(r"^ip route\s+", cfg),
    },
    {
        "key": "ospf",
        "category": "routing",
        "name": "OSPF",
        "status": NOT_SUPPORTED,
        "guidance": "OSPF is not supported in Cloud Configuration mode. Replace with static routes or redesign routing at the distribution layer.",
        "detect": lambda cfg: _find(r"^router ospf\s+\d+", cfg),
    },
    {
        "key": "eigrp",
        "category": "routing",
        "name": "EIGRP",
        "status": NOT_SUPPORTED,
        "guidance": "EIGRP is not supported in Cloud Configuration mode. Replace with static routes.",
        "detect": lambda cfg: _find(r"^router eigrp\s+\d+", cfg),
    },
    {
        "key": "bgp",
        "category": "routing",
        "name": "BGP",
        "status": NOT_SUPPORTED,
        "guidance": "BGP is not supported in Cloud Configuration mode.",
        "detect": lambda cfg: _find(r"^router bgp\s+\d+", cfg),
    },
    {
        "key": "pim",
        "category": "routing",
        "name": "IP Multicast (PIM)",
        "status": NOT_SUPPORTED,
        "guidance": "PIM multicast routing is not supported in Cloud Configuration mode.",
        "detect": lambda cfg: _find(r"ip pim\s+(sparse-mode|dense-mode|sparse-dense-mode)", cfg),
    },
    {
        "key": "ip_sla",
        "category": "routing",
        "name": "IP SLA",
        "status": NOT_SUPPORTED,
        "guidance": "IP SLA is not available in Cloud Configuration mode. Consider Dashboard alerts or external monitoring.",
        "detect": lambda cfg: _find(r"^ip sla\s+\d+", cfg),
    },

    # ── VLANs & L3 ───────────────────────────────────────────────────────────
    {
        "key": "vlans",
        "category": "switch",
        "name": "VLANs",
        "status": SUPPORTED,
        "guidance": "VLANs must be created in Dashboard under Networks → VLANs before migration. Port VLAN assignments are translatable.",
        "detect": lambda cfg: _find_all(r"^vlan\s+\d+", cfg),
    },
    {
        "key": "svi",
        "category": "routing",
        "name": "Layer 3 SVIs (interface Vlan)",
        "status": TRANSLATABLE,
        "guidance": "SVI IP addresses are translatable. Verify subnet and gateway configuration in Dashboard post-migration.",
        "detect": lambda cfg: _find_all(r"^interface Vlan\d+", cfg),
    },
    {
        "key": "private_vlan",
        "category": "switch",
        "name": "Private VLANs",
        "status": TRANSLATABLE,
        "guidance": "Private VLANs are supported and translatable via the Dashboard API.",
        "detect": lambda cfg: _find(r"^(private-vlan|switchport mode private-vlan)", cfg),
    },

    # ── Port features ─────────────────────────────────────────────────────────
    {
        "key": "port_description",
        "category": "port",
        "name": "Port Descriptions",
        "status": TRANSLATABLE,
        "guidance": "Port descriptions are automatically applied to Meraki port names.",
        "detect": lambda cfg: _find_all(r"^\s+description\s+.+", cfg),
    },
    {
        "key": "port_speed_duplex",
        "category": "port",
        "name": "Port Speed / Duplex",
        "status": TRANSLATABLE,
        "guidance": "Speed and duplex settings are translatable to Dashboard port configuration.",
        "detect": lambda cfg: _find_all(r"^\s+(speed|duplex)\s+\S+", cfg),
    },
    {
        "key": "poe",
        "category": "port",
        "name": "PoE (Power over Ethernet)",
        "status": TRANSLATABLE,
        "guidance": "PoE enabled/disabled per-port is translatable. PoE limits are configurable in Dashboard.",
        "detect": lambda cfg: _find(r"^\s+power inline (never|consumption|static)", cfg),
    },
    {
        "key": "access_vlan",
        "category": "port",
        "name": "Access VLAN (switchport access vlan)",
        "status": TRANSLATABLE,
        "guidance": "Access VLAN assignments are translatable automatically.",
        "detect": lambda cfg: _find_all(r"^\s+switchport access vlan\s+\d+", cfg),
    },
    {
        "key": "voice_vlan",
        "category": "port",
        "name": "Voice VLAN",
        "status": TRANSLATABLE,
        "guidance": "Voice VLAN is translatable to Dashboard port configuration.",
        "detect": lambda cfg: _find_all(r"^\s+switchport voice vlan\s+\d+", cfg),
    },
    {
        "key": "trunk_allowed_vlans",
        "category": "port",
        "name": "Trunk Allowed VLANs",
        "status": TRANSLATABLE,
        "guidance": "Trunk allowed VLAN lists are translatable. Verify after migration.",
        "detect": lambda cfg: _find_all(r"^\s+switchport trunk allowed vlan\s+", cfg),
    },
    {
        "key": "etherchannel_lacp",
        "category": "port",
        "name": "EtherChannel / LACP",
        "status": TRANSLATABLE,
        "guidance": "LACP port-channel groups are translatable. Verify channel-group membership in Dashboard.",
        "detect": lambda cfg: _find_all(r"^\s+channel-group\s+\d+\s+mode\s+(active|passive)", cfg),
    },
    {
        "key": "etherchannel_pagp",
        "category": "port",
        "name": "EtherChannel / PAgP",
        "status": PARTIAL,
        "guidance": "Meraki only supports LACP. PAgP channel groups must be converted to LACP or static before migration.",
        "detect": lambda cfg: _find_all(r"^\s+channel-group\s+\d+\s+mode\s+(desirable|auto)", cfg),
    },
    {
        "key": "stp_portfast",
        "category": "port",
        "name": "STP PortFast (per-port)",
        "status": TRANSLATABLE,
        "guidance": "PortFast is translatable per-port to Dashboard.",
        "detect": lambda cfg: _find_all(r"^\s+spanning-tree portfast", cfg),
    },
    {
        "key": "stp_bpduguard",
        "category": "port",
        "name": "STP BPDU Guard",
        "status": TRANSLATABLE,
        "guidance": "BPDU Guard is translatable per-port to Dashboard.",
        "detect": lambda cfg: _find_all(r"^\s+spanning-tree bpduguard enable", cfg),
    },
    {
        "key": "stp_rootguard",
        "category": "port",
        "name": "STP Root Guard",
        "status": TRANSLATABLE,
        "guidance": "Root Guard is translatable per-port to Dashboard.",
        "detect": lambda cfg: _find_all(r"^\s+spanning-tree guard root", cfg),
    },
    {
        "key": "stp_loopguard",
        "category": "port",
        "name": "STP Loop Guard",
        "status": TRANSLATABLE,
        "guidance": "Loop Guard is translatable per-port to Dashboard.",
        "detect": lambda cfg: _find_all(r"^\s+spanning-tree guard loop", cfg),
    },
    {
        "key": "storm_control",
        "category": "port",
        "name": "Storm Control",
        "status": NOT_SUPPORTED,
        "guidance": "Storm control thresholds are not configurable in Cloud Configuration mode.",
        "detect": lambda cfg: _find(r"^\s+storm-control\s+(broadcast|multicast|unicast)", cfg),
    },
    {
        "key": "port_security",
        "category": "port",
        "name": "Port Security (switchport port-security)",
        "status": NOT_SUPPORTED,
        "guidance": "IOS XE port-security is not available in Cloud Config mode. Use Dashboard's Client Allowlist or Policy features as an alternative.",
        "detect": lambda cfg: _find(r"^\s+switchport port-security", cfg),
    },
    {
        "key": "dot1x_port",
        "category": "security",
        "name": "802.1X Port Authentication",
        "status": SUPPORTED,
        "guidance": "802.1X is supported in Dashboard via Policy → RADIUS settings. Configure RADIUS server and apply policy per port.",
        "detect": lambda cfg: _find(r"^\s+dot1x pae authenticator", cfg),
    },
    {
        "key": "mab",
        "category": "security",
        "name": "MAC Authentication Bypass (MAB)",
        "status": SUPPORTED,
        "guidance": "MAB is supported in Meraki via Policy. Configure in Dashboard under Network-wide → Group Policies.",
        "detect": lambda cfg: _find(r"^\s+mab", cfg),
    },

    # ── Security ──────────────────────────────────────────────────────────────
    {
        "key": "acl_extended",
        "category": "security",
        "name": "Extended ACLs (ip access-list extended)",
        "status": NOT_SUPPORTED,
        "guidance": "Extended ACLs are not directly supported in Cloud Config mode. Use Meraki Group Policies and Traffic Shaping rules to approximate Layer 3/4 filtering.",
        "detect": lambda cfg: _find_all(r"^ip access-list extended\s+\S+", cfg),
    },
    {
        "key": "acl_standard",
        "category": "security",
        "name": "Standard ACLs (ip access-list standard)",
        "status": NOT_SUPPORTED,
        "guidance": "Standard ACLs are not supported in Cloud Config mode. Use Group Policies for client-level access control.",
        "detect": lambda cfg: _find_all(r"^ip access-list standard\s+\S+", cfg),
    },
    {
        "key": "acl_mac",
        "category": "security",
        "name": "MAC ACLs (mac access-list extended)",
        "status": NOT_SUPPORTED,
        "guidance": "MAC ACLs are not supported in Cloud Config mode.",
        "detect": lambda cfg: _find(r"^mac access-list extended", cfg),
    },
    {
        "key": "dhcp_snooping",
        "category": "security",
        "name": "DHCP Snooping",
        "status": SUPPORTED,
        "guidance": "DHCP snooping is enabled by default in Meraki Cloud Config. Trusted uplink ports are configured automatically.",
        "detect": lambda cfg: _find(r"^ip dhcp snooping", cfg),
    },
    {
        "key": "dynamic_arp_inspection",
        "category": "security",
        "name": "Dynamic ARP Inspection (DAI)",
        "status": SUPPORTED,
        "guidance": "ARP inspection is enabled by default in Meraki Cloud Config. No manual configuration required.",
        "detect": lambda cfg: _find(r"^ip arp inspection vlan", cfg),
    },
    {
        "key": "ip_source_guard",
        "category": "security",
        "name": "IP Source Guard",
        "status": NOT_SUPPORTED,
        "guidance": "IP Source Guard is not available in Cloud Config mode. DHCP snooping provides partial protection.",
        "detect": lambda cfg: _find(r"^\s+ip verify source", cfg),
    },
    {
        "key": "radius",
        "category": "security",
        "name": "RADIUS Server Configuration",
        "status": SUPPORTED,
        "guidance": "Configure RADIUS in Dashboard under Network-wide → RADIUS servers. Used for 802.1X and admin authentication.",
        "detect": lambda cfg: _find_all(r"^radius(-server|\s+server)\s+\S+", cfg),
    },
    {
        "key": "tacacs",
        "category": "security",
        "name": "TACACS+ (AAA)",
        "status": NOT_SUPPORTED,
        "guidance": "TACACS+ is not supported in Cloud Config mode. Admin authentication uses Meraki Dashboard accounts and SAML/RADIUS only.",
        "detect": lambda cfg: _find(r"^(tacacs-server|tacacs\s+server)\s+\S+", cfg),
    },
    {
        "key": "aaa_accounting",
        "category": "security",
        "name": "AAA Accounting",
        "status": NOT_SUPPORTED,
        "guidance": "AAA accounting is not configurable in Cloud Config mode. Dashboard provides audit logs for admin actions.",
        "detect": lambda cfg: _find(r"^aaa accounting", cfg),
    },
    {
        "key": "crypto_pki",
        "category": "security",
        "name": "PKI / Crypto Certificates",
        "status": NOT_SUPPORTED,
        "guidance": "IOS XE PKI configuration is not applicable in Cloud Config mode. Meraki uses its own certificate infrastructure.",
        "detect": lambda cfg: _find(r"^crypto pki", cfg),
    },

    # ── QoS ──────────────────────────────────────────────────────────────────
    {
        "key": "qos_mls",
        "category": "qos",
        "name": "MLS QoS (mls qos)",
        "status": NOT_SUPPORTED,
        "guidance": "MLS QoS is not available in Cloud Config mode. Use Meraki Traffic Shaping rules in Dashboard under SD-WAN & Traffic Shaping.",
        "detect": lambda cfg: _find(r"^mls qos", cfg),
    },
    {
        "key": "qos_policy_map",
        "category": "qos",
        "name": "QoS Policy-Map / Class-Map",
        "status": NOT_SUPPORTED,
        "guidance": "IOS XE MQC policy-maps are not supported. Meraki provides application-aware traffic shaping — recreate policies in Dashboard.",
        "detect": lambda cfg: _find_all(r"^policy-map\s+\S+", cfg),
    },
    {
        "key": "qos_dscp_trust",
        "category": "qos",
        "name": "QoS DSCP Trust",
        "status": SUPPORTED,
        "guidance": "Meraki honours DSCP markings by default in Cloud Config mode. Explicit configuration is not required.",
        "detect": lambda cfg: _find(r"^\s+(mls qos trust dscp|auto qos)", cfg),
    },
    {
        "key": "auto_qos",
        "category": "qos",
        "name": "Auto QoS (auto qos voip/trust)",
        "status": NOT_SUPPORTED,
        "guidance": "Auto QoS macros are not available in Cloud Config mode. Manually configure voice traffic shaping in Dashboard.",
        "detect": lambda cfg: _find(r"^\s+auto qos", cfg),
    },

    # ── Management ────────────────────────────────────────────────────────────
    {
        "key": "snmp_v2",
        "category": "management",
        "name": "SNMP v2c",
        "status": SUPPORTED,
        "guidance": "SNMP v2c is supported in Dashboard under Network-wide → General → Reporting. Configure community string and trap receivers.",
        "detect": lambda cfg: _find(r"^snmp-server community\s+\S+\s+RO", cfg),
    },
    {
        "key": "snmp_v3",
        "category": "management",
        "name": "SNMP v3",
        "status": NOT_SUPPORTED,
        "guidance": "SNMP v3 is not supported in Cloud Config mode. Use SNMP v2c or Meraki API for monitoring.",
        "detect": lambda cfg: _find(r"^snmp-server (user|group)\s+\S+.*v3", cfg),
    },
    {
        "key": "snmp_traps",
        "category": "management",
        "name": "SNMP Traps",
        "status": SUPPORTED,
        "guidance": "SNMP trap receivers can be configured in Dashboard under Network-wide → Alerts.",
        "detect": lambda cfg: _find_all(r"^snmp-server host\s+\S+", cfg),
    },
    {
        "key": "syslog",
        "category": "management",
        "name": "Syslog",
        "status": SUPPORTED,
        "guidance": "Syslog server(s) can be configured in Dashboard under Network-wide → General → Logging.",
        "detect": lambda cfg: _find_all(r"^logging\s+host\s+\S+|^logging\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cfg),
    },
    {
        "key": "ntp_server",
        "category": "management",
        "name": "NTP Servers",
        "status": SUPPORTED,
        "guidance": "NTP is managed centrally by Meraki in Cloud Config mode. Custom NTP servers cannot be specified — Meraki uses its own time infrastructure.",
        "detect": lambda cfg: _find_all(r"^ntp server\s+\S+", cfg),
    },
    {
        "key": "netflow",
        "category": "management",
        "name": "NetFlow / IP Flow",
        "status": NOT_SUPPORTED,
        "guidance": "NetFlow export is not available in Cloud Config mode. Meraki provides traffic analytics natively in Dashboard.",
        "detect": lambda cfg: _find(r"^(ip flow-export|flow record|flow monitor)", cfg),
    },
    {
        "key": "erspan",
        "category": "management",
        "name": "ERSPAN / SPAN Port Mirroring",
        "status": SUPPORTED,
        "guidance": "Port mirroring (SPAN) is supported in Dashboard under Switch → Ports. Configure via Dashboard UI.",
        "detect": lambda cfg: _find(r"^monitor session\s+\d+", cfg),
    },
    {
        "key": "banner",
        "category": "management",
        "name": "Login Banner",
        "status": NOT_SUPPORTED,
        "guidance": "Custom login banners are not configurable in Cloud Config mode.",
        "detect": lambda cfg: _find(r"^banner\s+(motd|login|exec)", cfg),
    },
    {
        "key": "ssh_config",
        "category": "management",
        "name": "SSH Configuration",
        "status": SUPPORTED,
        "guidance": "SSH access to the device is managed through Dashboard. Local SSH config is replaced by Meraki's secure tunnel management.",
        "detect": lambda cfg: _find(r"^ip ssh (version|time-out|authentication-retries)", cfg),
    },
    {
        "key": "local_users",
        "category": "management",
        "name": "Local User Accounts",
        "status": NOT_SUPPORTED,
        "guidance": "Local user accounts are not used in Cloud Config mode. Admin access is via Dashboard SSO. Device-level credentials are managed by Meraki.",
        "detect": lambda cfg: _find_all(r"^username\s+\S+\s+(privilege|secret|password)", cfg),
    },
    {
        "key": "ntp_acl",
        "category": "management",
        "name": "NTP Access Control",
        "status": NOT_SUPPORTED,
        "guidance": "NTP ACLs are not applicable in Cloud Config mode.",
        "detect": lambda cfg: _find(r"^ntp access-group", cfg),
    },
    {
        "key": "http_server",
        "category": "management",
        "name": "HTTP / HTTPS Server",
        "status": NOT_SUPPORTED,
        "guidance": "The local IOS web server is not used in Cloud Config mode. Management is entirely via Dashboard.",
        "detect": lambda cfg: _find(r"^ip http (server|secure-server)", cfg),
    },
]


# ── Analyzer class ─────────────────────────────────────────────────────────────

class ConfigAnalyzer:
    def __init__(self, host: str, username: str, password: str,
                 port: int = 22, secret: Optional[str] = None):
        self.host     = host
        self.username = username
        self.password = password
        self.port     = port
        self.secret   = secret or password
        self.conn     = None

    def _connect(self):
        return ConnectHandler(
            device_type="cisco_ios",
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            secret=self.secret,
            timeout=30,
            auth_timeout=20,
            fast_cli=False,
        )

    def _get_running_config(self) -> str:
        return self.conn.send_command("show running-config", read_timeout=60)

    async def analyze(self) -> AnalysisResult:
        result = AnalysisResult(host=self.host)
        try:
            loop = asyncio.get_event_loop()
            self.conn = await loop.run_in_executor(None, self._connect)
            cfg = await loop.run_in_executor(None, self._get_running_config)
            self.conn.disconnect()
        except Exception as e:
            result.error = str(e)
            logger.error("ConfigAnalyzer SSH error for %s: %s", self.host, e)
            return result

        return self._classify(result, cfg)

    async def analyze_from_text(self, config_text: str) -> AnalysisResult:
        """Analyse a config provided directly as a string (offline mode — no SSH needed).
        
        Also runs static checks that can be determined purely from config text:
        NTP server, DNS name-server, AAA new-model, IP routing, domain lookup, HTTP client source-interface.
        Live checks (NTP sync, DNS resolution, connectivity, privilege level) are skipped.
        """
        result = AnalysisResult(host="(config file)")
        result = self._classify(result, config_text)
        result.static_checks = self._parse_static_checks(config_text)
        return result

    def _parse_static_checks(self, cfg: str) -> dict:
        """
        Parse config-static prerequisite items from a raw IOS XE config string.
        Returns a dict of check-key → value (bool or str). Only checks that can be
        determined without a live device are included.
        """
        import re
        checks = {}

        # NTP server configured
        m = re.search(r"^ntp server\s+(\S+)", cfg, re.IGNORECASE | re.MULTILINE)
        checks["ntpConfigured"] = m.group(1) if m else False

        # DNS name-server configured
        m = re.search(r"^ip name-server\s+(\S+)", cfg, re.IGNORECASE | re.MULTILINE)
        checks["dnsConfigured"] = m.group(1) if m else False

        # AAA new-model
        checks["aaaNewModel"] = bool(re.search(r"^aaa new-model", cfg, re.IGNORECASE | re.MULTILINE))

        # IP routing
        checks["ipRouting"] = bool(re.search(r"^ip routing", cfg, re.IGNORECASE | re.MULTILINE))

        # Domain lookup (absent of 'no ip domain lookup' means enabled)
        no_lookup = bool(re.search(r"no ip domain.lookup", cfg, re.IGNORECASE | re.MULTILINE))
        checks["domainLookup"] = not no_lookup

        # HTTP client source-interface
        m = re.search(r"ip http client source-interface\s+(\S+)", cfg, re.IGNORECASE | re.MULTILINE)
        checks["httpClientSrc"] = m.group(1) if m else False

        # IOS XE version from config banner/boot statement (best-effort)
        m = re.search(r"^version\s+([\d.]+)", cfg, re.IGNORECASE | re.MULTILINE)
        if m:
            checks["iosVersion"] = m.group(1)

        return checks

    def _classify(self, result: AnalysisResult, cfg: str) -> AnalysisResult:
        for entry in FEATURE_ENCYCLOPEDIA:
            detected, detected_val = entry["detect"](cfg)
            fr = FeatureResult(
                key          = entry["key"],
                category     = entry["category"],
                name         = entry["name"],
                status       = entry["status"],
                detected     = detected,
                detected_val = detected_val,
                guidance     = entry["guidance"],
            )
            result.features.append(fr)

        # Populate summary counts (only for detected features)
        for f in result.features:
            if f.detected:
                result.n_detected += 1
                if f.status == TRANSLATABLE:
                    result.n_translatable += 1
                elif f.status == SUPPORTED:
                    result.n_supported += 1
                elif f.status == PARTIAL:
                    result.n_partial += 1
                elif f.status == NOT_SUPPORTED:
                    result.n_not_supported += 1

        return result


def result_to_dict(r: AnalysisResult) -> dict:
    """Serialise AnalysisResult to a plain dict for JSON response."""
    d = {
        "host":            r.host,
        "error":           r.error,
        "n_detected":      r.n_detected,
        "n_translatable":  r.n_translatable,
        "n_supported":     r.n_supported,
        "n_partial":       r.n_partial,
        "n_not_supported": r.n_not_supported,
        "features": [
            {
                "key":          f.key,
                "category":     f.category,
                "name":         f.name,
                "status":       f.status,
                "detected":     f.detected,
                "detected_val": f.detected_val,
                "guidance":     f.guidance,
            }
            for f in r.features
        ],
    }
    if r.static_checks is not None:
        d["static_checks"] = r.static_checks
    return d

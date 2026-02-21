"""
models.py — Pydantic request/response models for the Meraki onboarding API.
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime


class DeviceRequest(BaseModel):
    host: str = Field(..., description="Switch IP address or hostname")
    username: str = Field(..., description="SSH username (must be privilege-15)")
    password: str = Field(..., description="SSH password")
    port: int = Field(default=22, description="SSH port")
    mode: Literal["device", "cloud"] = Field(
        default="device",
        description="'device' = Device Configuration mode, 'cloud' = Cloud Configuration mode"
    )
    secret: Optional[str] = Field(default=None, description="Enable secret (if required)")
    skip_connect: bool = Field(default=False, description="If True, stop after prereq checks without issuing service meraki connect (readiness check mode)")

    model_config = {"json_schema_extra": {"example": {"host": "192.168.1.10", "username": "admin", "password": "Cisco123!", "port": 22, "mode": "device"}}}


class BulkRequest(BaseModel):
    """
    Bulk onboarding request — SSH into N devices, then claim all to Meraki Dashboard via API.
    """
    devices: list[DeviceRequest] = Field(..., description="List of devices to onboard")
    meraki_api_key: str = Field(..., description="Meraki Dashboard API key")
    org_id: str = Field(..., description="Meraki Organization ID")
    network_id: str = Field(..., description="Meraki Network ID to add devices to")
    add_atomically: bool = Field(
        default=False,
        description="If True, all devices must succeed or none are added to the network"
    )

    model_config = {"json_schema_extra": {"example": {
                "meraki_api_key": "your-api-key-here",
                "org_id": "123456",
                "network_id": "L_646829496481105433",
                "add_atomically": False,
                "devices": [
                    {"host": "192.168.1.10", "username": "admin", "password": "Cisco123!", "mode": "device"},
                    {"host": "192.168.1.11", "username": "admin", "password": "Cisco123!", "mode": "cloud"},
                ]
}}}


class PrereqChecks(BaseModel):
    # Common checks
    connected: Optional[bool] = None
    ios_version: Optional[str] = None
    ios_ok: Optional[bool] = None
    ntp_configured: Optional[bool] = None
    ntp_synced: Optional[bool] = None
    dns_configured: Optional[bool] = None
    dns_resolvable: Optional[bool] = None
    meraki_reachable: Optional[bool] = None
    # Device Config mode
    aaa_new_model: Optional[bool] = None
    ip_routing: Optional[bool] = None
    ip_domain_lookup: Optional[bool] = None
    privilege_level: Optional[int] = None
    # Cloud Config mode
    meraki_compatibility: Optional[bool] = None
    install_mode: Optional[bool] = None
    full_encryption: Optional[bool] = None
    http_client_source: Optional[bool] = None


class MerakiApiResult(BaseModel):
    claimed_to_org: Optional[bool] = None
    added_to_network: Optional[bool] = None
    org_id: Optional[str] = None
    network_id: Optional[str] = None
    api_error: Optional[str] = None


class LogEntry(BaseModel):
    time: str
    msg: str
    color: Optional[str] = None


class CheckResult(BaseModel):
    host: str
    mode: str
    status: Literal["idle", "checking", "onboarding", "done", "failed"]
    cloud_id: Optional[str] = None
    checks: PrereqChecks = Field(default_factory=PrereqChecks)
    meraki_api: MerakiApiResult = Field(default_factory=MerakiApiResult)
    logs: list[LogEntry] = []
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class BulkJobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "done", "failed"]
    total: int
    completed: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[CheckResult] = []
    meraki_claim_result: Optional[dict] = None
    meraki_network_result: Optional[dict] = None

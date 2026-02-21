# Testing Guide — Catalyst → Meraki Onboarding

---

## Quick Start

```bash
# Install test dependencies (from this directory)
pip install -r requirements-test.txt

# Run unit tests only (no switches or API key needed)
pytest -v

# Run unit tests + integration tests (real switches needed)
pytest -v -m "integration" --no-header

# Run everything including end-to-end (claims real devices!)
pytest -v -m "integration or e2e"
```

---

## Test Layers

### 1. Unit Tests — No real hardware needed

All SSH and Meraki API calls are mocked. Fast, safe, runs anywhere.

| File | What it tests |
|------|---------------|
| `test_device_checker.py` | SSH checks, version parsing, prerequisite logic, Cloud-ID parsing |
| `test_meraki_api.py` | API payload construction, error handling, credential passing |
| `test_bulk_orchestrator.py` | Concurrency, partial failures, API phase skipping, WebSocket events |

```bash
pytest test_device_checker.py -v
pytest test_meraki_api.py -v
pytest test_bulk_orchestrator.py -v
```

**Key things verified by unit tests:**
- IOS XE 17.15.3+ passes for Device Config; 17.14.x fails
- IOS XE 17.15.0+ passes for Cloud Config
- Device Config → Meraki API payload uses `"monitored"` + credentials
- Cloud Config → Meraki API payload uses `"managed"` (no credentials, triggers factory reset)
- `add_atomically` flag correctly flows through to the API body
- All 4 SSH failure modes handled: auth failure, timeout, version too old, no Cloud ID

---

### 2. Integration Tests — Real switches required

Connects to actual Cisco Catalyst 9K switches over SSH.

**Setup:**
```bash
cp .env.example .env
# Edit .env with your switch IPs, credentials, and Meraki API key
```

```bash
# SSH checks only (no Meraki API calls, no service meraki connect)
pytest test_integration.py::TestRealSwitchChecks::test_full_prereq_check_device_mode -v -s

# Verify Meraki API key + list networks (no switch needed)
pytest test_integration.py::TestRealMerakiAPI -v -s

# All integration tests (SSH + API, but NOT service meraki connect)
pytest test_integration.py -v -s -m "integration and not e2e"
```

---

### 3. End-to-End Tests — Claims real devices!

⚠️ These tests issue `service meraki connect` on your switches and claim them to your Meraki org. Only run against dedicated test switches.

```bash
pytest test_integration.py::TestRealEndToEnd -v -s -m "e2e"
```

---

## Postman Collection

Import `Catalyst-Meraki-Onboarding.postman_collection.json` into Postman.

**Setup:**
1. Open the collection → Variables tab
2. Set `base_url` (default: `http://localhost:8000`)
3. Set `meraki_api_key`, `org_id`, `network_id`
4. Set `switch_host`, `switch_user`, `switch_pass`

**Recommended test order:**
1. `1 — System / Health Check` — confirm server is up
2. `2 — Meraki API Utilities / Verify API Key` — validate credentials
3. `2 — Meraki API Utilities / List Networks` — find your network_id
4. `3 — Single Device Check / Check Device — Device Config Mode` — test one switch
5. `4 — Bulk Onboarding / Start Bulk Job` → then `Poll Job Status`

**Negative tests included:**
- Bad SSH credentials → `status: failed`
- Unreachable host → graceful SSH timeout
- Invalid Meraki API key → 401 on verify, API phase fails in bulk job
- Non-existent job_id → 404

---

## Interpreting Results

### Device check result
```json
{
  "host": "192.168.1.10",
  "mode": "device",
  "status": "done",
  "cloud_id": "N_ABCD1234EF",
  "checks": {
    "connected": true,
    "ios_version": "17.15.3",
    "ios_ok": true,
    "ntp_configured": true,
    "ntp_synced": true,
    "dns_configured": true,
    "dns_resolvable": true,
    "meraki_reachable": true,
    "aaa_new_model": true,
    "ip_routing": true,
    "ip_domain_lookup": true,
    "privilege_level": 15
  }
}
```

### Common failures and fixes

| Failure | Cause | Fix |
|---------|-------|-----|
| `connected: false` | SSH auth failed or unreachable | Check IP, credentials, ACLs |
| `ios_ok: false` | IOS XE below 17.15.3 | Upgrade to 17.15.3+ before onboarding |
| `ntp_synced: false` | NTP not synced | Fix NTP server reachability |
| `dns_resolvable: false` | Can't reach dashboard.meraki.com | Check DNS + internet route |
| `aaa_new_model: false` | AAA not configured | Add `aaa new-model` to config |
| `ip_routing: false` | IP routing disabled | Add `ip routing` |
| `install_mode: false` | Switch in bundle mode | Convert to install mode first |
| `full_encryption: false` | NPE image | Replace with full-encryption image |
| `cloud_id: null` | Tunnel never came up | Check TCP/443 to *.meraki.com |

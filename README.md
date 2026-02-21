# Catalyst → Meraki Onboarding

A full-stack tool for migrating Cisco Catalyst 9K switches to Cisco Meraki. Combines an SSH-based prerequisite checker, IOS XE config compatibility analyser, and Meraki Dashboard API integration into a single browser-based GUI.

---

## What it does

**Readiness Check mode** — SSH into Catalyst switches and validate every prerequisite for Meraki onboarding before touching anything in production:
- IOS XE version (17.15.3+ for Device Config, 17.15.0+ for Cloud Config)
- NTP configuration and clock sync
- DNS name-server and Meraki Dashboard reachability
- AAA new-model, IP routing, domain lookup (Device Config mode)
- Install mode, full encryption image, HTTP client source-interface (Cloud Config mode)
- Optionally issues `service meraki connect` to retrieve the Cloud ID for your records

**Config Compatibility Analysis** — maps every detected IOS XE feature in the running config against its Meraki equivalent, categorised as auto-translatable, manual config required, partial support, or not supported. Also works offline against an uploaded config file.

**Automated Onboarding mode** — takes devices that have passed readiness checks and runs the complete onboarding pipeline end-to-end:
1. SSH prereq checks
2. `service meraki connect` → Cloud ID
3. Claim device to Meraki org inventory
4. Add to target network
5. Mode validation (monitored vs managed)
6. Direct link to the Meraki Dashboard switching page on completion

---

## Architecture

```
index.html          Single-file React frontend (no build step)
app.py              FastAPI backend — REST + WebSocket endpoints
device_checker.py   SSH prerequisite checker via Netmiko
config_analyzer.py  IOS XE feature detection and Meraki mapping
meraki_api.py       Meraki Dashboard API client
bulk_orchestrator.py  Async bulk job runner
models.py           Pydantic request/response models
cli.py              Optional command-line interface
```

The frontend connects to the backend over HTTP (REST) and WebSocket. WebSocket streams live SSH logs and check results to the browser in real time as each check completes.

---

## Requirements

- Python 3.11+
- Network access to your Catalyst switches over SSH (port 22)
- Meraki Dashboard API key with org write access (for Automated Onboarding)
- Switches must be privilege-15 accessible

---

## Installation

```bash
git clone https://github.com/ryanpascoe/catalyst-meraki-onboarding.git
cd catalyst-meraki-onboarding

pip install -r requirements.txt
```

---

## Running

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Then open [http://localhost:8000](http://localhost:8000) in your browser. The frontend is served directly from the FastAPI app — no separate web server needed.

---

## Usage

### Readiness Check

1. Select **Readiness Check** mode (default)
2. Add a device — enter host/IP, SSH credentials, port, and enable secret
3. Choose **Device Config** or **Cloud Config** mode
4. Click **▶ Run Readiness Check**
5. Watch checks complete in real time in the Checks tab
6. If all checks pass, either:
   - **▶ Retrieve Cloud ID for Manual Onboarding** — issues `service meraki connect` and records the Cloud ID without claiming the device
   - **⚡ Add to Automated Onboarding** — copies the device (with all check results) into the onboarding queue

You can also upload a static IOS XE config file (`.txt`, `.conf`, `.cfg`) for offline analysis — SSH checks are skipped but static config items (NTP, DNS, AAA, routing) are parsed from the file.

**Bulk import:** upload a CSV with columns `host, username, password, port, mode, secret` to add multiple devices at once.

### Config Compatibility Analysis

Click the **Config Analysis** tab on any device to run a feature compatibility report. In **Device Config mode** all detected features are shown as supported. In **Cloud Config mode** features are classified individually.

### Automated Onboarding

1. Switch to **Automated Onboarding** mode
2. Enter your **Meraki API Key** and **Organization ID** — available networks load automatically into a dropdown
3. Devices promoted from Readiness Check appear in the queue with their check results already carried over
4. Select each device and choose its **target network** from the dropdown
5. Click **⚡ Onboard** per device or **⚡ Onboard All** to run the full pipeline
6. On completion a **🔗 View in Meraki Dashboard** link takes you directly to the switching page for that network

---

## Onboarding modes explained

| Mode | IOS XE minimum | What Meraki does | Meraki API mode |
|------|---------------|-----------------|----------------|
| Device Config | 17.15.3+ | Manages device via SSH, config stays on switch | `monitored` |
| Cloud Config | 17.15.0+ | Full cloud management, factory reset applied | `managed` |

---

## API reference

The FastAPI backend exposes an interactive API docs page at [http://localhost:8000/docs](http://localhost:8000/docs).

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `WS` | `/ws/check` | Real-time SSH prereq check stream |
| `POST` | `/api/analyze-config` | Config compatibility analysis (live or offline) |
| `GET` | `/api/meraki/networks` | List networks for an org |
| `POST` | `/api/meraki/claim` | Claim device to org inventory |
| `POST` | `/api/meraki/network-claim` | Add device to a network |
| `GET` | `/api/meraki/verify-mode` | Poll device mode after claiming |
| `POST` | `/api/bulk/start` | Start a bulk onboarding job |
| `GET` | `/api/bulk/{job_id}` | Poll bulk job status |

A Postman collection is included: import `Catalyst-Meraki-Onboarding_postman_collection.json` and set the `base_url`, `meraki_api_key`, `org_id`, `network_id`, and switch credential variables.

---

## Testing

```bash
pip install -r requirements-test.txt

# Unit tests — no switches or API key needed
pytest -v

# Integration tests — requires real switches (configure .env first)
pytest -v -m "integration" -s

# End-to-end — issues service meraki connect and claims real devices
pytest -v -m "e2e" -s
```

| Test file | What it covers |
|-----------|---------------|
| `test_device_checker.py` | SSH checks, version parsing, prerequisite logic |
| `test_meraki_api.py` | API payload construction, error handling |
| `test_bulk_orchestrator.py` | Concurrency, partial failures, WebSocket events |
| `test_integration.py` | Real switch SSH + live Meraki API calls |

---

## Common failures and fixes

| Check | Failure | Fix |
|-------|---------|-----|
| SSH Connection | `connected: false` | Verify IP reachability, credentials, and SSH ACLs |
| IOS XE Version | `ios_ok: false` | Upgrade to 17.15.3+ (Device Config) or 17.15.0+ (Cloud Config) |
| NTP Synced | `ntp_synced: false` | Fix NTP server reachability and wait for sync |
| Meraki Reachable | `meraki_reachable: false` | Open TCP/443 to `*.meraki.com` |
| AAA New-Model | `aaa_new_model: false` | Add `aaa new-model` to global config |
| IP Routing | `ip_routing: false` | Add `ip routing` to global config |
| Domain Lookup | `domainLookup: false` | Remove `no ip domain-lookup` from config |
| Install Mode | `install_mode: false` | Convert from bundle to install boot mode |
| Full Encryption | `full_encryption: false` | Replace NPE image with full-encryption IOS XE |
| Cloud ID | `cloudId: null` | Check TCP/443 path to Meraki — tunnel may be blocked |

---

## Notes

- The backend stores bulk job state in memory. Restarting the server clears all jobs. For production use, replace the in-memory store with Redis or a database.
- CORS is set to `allow_origins=["*"]` for development. Restrict this to your frontend origin in production.
- SSH credentials are never stored on the server — they are used in memory for the duration of the check and discarded.

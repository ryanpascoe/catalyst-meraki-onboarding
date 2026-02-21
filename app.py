"""
app.py — FastAPI server.
Exposes REST + WebSocket endpoints for single-device and bulk onboarding.
"""

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from models import DeviceRequest, BulkRequest, CheckResult, BulkJobStatus
from device_checker import DeviceChecker
from bulk_orchestrator import BulkOrchestrator
from meraki_api import MerakiDashboardClient, MerakiAPIError
from config_analyzer import ConfigAnalyzer, result_to_dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

# In-memory job store (use Redis in production)
jobs: dict[str, BulkJobStatus] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Catalyst → Meraki Onboarding API started")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="Catalyst → Meraki Onboarding API",
    version="2.0.0",
    description=(
        "SSH-based prerequisite checker and Meraki Dashboard API integration "
        "for Cisco Catalyst 9K onboarding."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restrict to your frontend origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------ #
#  Health / info                                                       #
# ------------------------------------------------------------------ #

@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ------------------------------------------------------------------ #
#  Single-device endpoints                                             #
# ------------------------------------------------------------------ #

@app.post("/api/check", response_model=CheckResult, tags=["Single Device"])
async def check_device(req: DeviceRequest):
    """
    Run full SSH prerequisite check + service meraki connect on a single device.
    Returns the complete result synchronously.
    Use the WebSocket endpoint /ws/check for real-time streaming.
    """
    checker = DeviceChecker(req)
    return await checker.run()


@app.websocket("/ws/check")
async def websocket_check(websocket: WebSocket):
    """
    WebSocket — stream real-time SSH check output for a single device.

    Client sends (JSON):
        { "host": "...", "username": "...", "password": "...", "port": 22, "mode": "device" }

    Server streams events:
        { "type": "log",      "msg": "...", "color": "#00e676" }
        { "type": "check",    "key": "iosOk", "value": true }
        { "type": "progress", "pct": 45 }
        { "type": "done",     "result": { ...CheckResult } }
        { "type": "error",    "msg": "..." }
    """
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        req = DeviceRequest(**json.loads(raw))
        checker = DeviceChecker(req, ws=websocket)
        result = await checker.run()
        await websocket.send_json({"type": "done", "result": result.model_dump()})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "msg": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ------------------------------------------------------------------ #
#  Bulk endpoints                                                      #
# ------------------------------------------------------------------ #

@app.post("/api/bulk", tags=["Bulk"])
async def bulk_onboard(req: BulkRequest):
    """
    Enqueue a bulk onboarding job.
    Runs SSH checks on all devices concurrently, then calls Meraki Dashboard API
    to claim Cloud IDs into org inventory and add them to the specified network.

    Returns a job_id — poll /api/jobs/{job_id} or connect to /ws/bulk for streaming.
    """
    job_id = str(uuid.uuid4())
    job = BulkJobStatus(job_id=job_id, status="queued", total=len(req.devices))
    jobs[job_id] = job

    async def run():
        orch = BulkOrchestrator(req)
        orch.status = job
        result = await orch.run()
        jobs[job_id] = result

    asyncio.create_task(run())
    return {"job_id": job_id, "total": len(req.devices), "status": "queued"}


@app.get("/api/jobs/{job_id}", response_model=BulkJobStatus, tags=["Bulk"])
async def get_job(job_id: str):
    """Poll the status of a bulk onboarding job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/api/jobs", tags=["Bulk"])
async def list_jobs():
    """List all bulk jobs and their statuses."""
    return [
        {"job_id": j.job_id, "status": j.status, "total": j.total,
         "completed": j.completed, "succeeded": j.succeeded, "failed": j.failed}
        for j in jobs.values()
    ]


@app.websocket("/ws/bulk")
async def websocket_bulk(websocket: WebSocket):
    """
    WebSocket — stream real-time output for a bulk onboarding job.

    Client sends (JSON):
        {
          "meraki_api_key": "...",
          "org_id": "...",
          "network_id": "...",
          "add_atomically": false,
          "devices": [
            { "host": "...", "username": "...", "password": "...", "mode": "device" },
            ...
          ]
        }

    Server streams:
        { "type": "log",         "msg": "...", "color": "..." }       — global log
        { "type": "bulk_log",    "msg": "...", "color": "..." }       — orchestrator log
        { "type": "bulk_status", "status": { ...BulkJobStatus } }    — full status update
        { "type": "done",        "status": { ...BulkJobStatus } }    — final result
        { "type": "error",       "msg": "..." }                       — fatal error
    """
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        req = BulkRequest(**json.loads(raw))
        orch = BulkOrchestrator(req, ws=websocket)
        result = await orch.run()
        await websocket.send_json({"type": "done", "status": result.model_dump()})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "msg": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ------------------------------------------------------------------ #
#  Meraki API utility endpoints                                        #
# ------------------------------------------------------------------ #

@app.get("/api/meraki/verify", tags=["Meraki API"])
async def verify_meraki_key(api_key: str, org_id: str):
    """
    Verify a Meraki API key has access to the given organization.
    Useful for validating credentials before running a bulk job.
    """
    client = MerakiDashboardClient(api_key)
    ok, name = await client.verify_api_key(org_id)
    if ok:
        return {"valid": True, "org_name": name}
    return JSONResponse(status_code=401, content={"valid": False, "error": name})


@app.get("/api/meraki/networks", tags=["Meraki API"])
async def list_networks(api_key: str, org_id: str):
    """List all networks in a Meraki organization — useful for selecting a target network_id."""
    client = MerakiDashboardClient(api_key)
    try:
        networks = await client.list_networks(org_id)
        return [{"id": n["id"], "name": n["name"], "type": n.get("productTypes", [])} for n in networks]
    except MerakiAPIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.post("/api/meraki/claim", tags=["Meraki API"])
async def claim_to_org(body: dict):
    """
    Claim one or more Cloud IDs into org inventory.
    Body: { api_key, org_id, cloud_ids: [str] }
    """
    client = MerakiDashboardClient(body["api_key"])
    try:
        result = await client.claim_into_org_inventory(body["org_id"], body["cloud_ids"])
        return {"claimed": body["cloud_ids"], "result": result}
    except MerakiAPIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.post("/api/meraki/network-claim", tags=["Meraki API"])
async def claim_to_network(body: dict):
    """
    Add devices to a network with operating mode.
    Body: { api_key, network_id, devices: [{cloud_id, mode, username, password, secret}], add_atomically }
    """
    client = MerakiDashboardClient(body["api_key"])
    try:
        result = await client.add_devices_to_network(
            network_id=body["network_id"],
            devices=body["devices"],
            add_atomically=body.get("add_atomically", False),
        )
        return {"result": result}
    except MerakiAPIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.get("/api/meraki/verify-mode", tags=["Meraki API"])
async def verify_mode(api_key: str, org_id: str, cloud_id: str, expected_mode: str):
    """
    Check if a device's Cloud configuration in inventory matches expected mode.
    expected_mode: 'monitored' (device config) or 'managed' (cloud config)
    """
    client = MerakiDashboardClient(api_key)
    match, actual = await client.verify_device_mode(cloud_id, org_id, expected_mode)
    return {"match": match, "actual": actual, "expected": expected_mode}


# ------------------------------------------------------------------ #
#  Config compatibility analysis                                       #
# ------------------------------------------------------------------ #

@app.post("/api/analyze-config", tags=["Config Analysis"])
async def analyze_config(body: dict):
    """
    Analyse IOS XE config against the Meraki Cloud Configuration support matrix.

    Two modes:
      Live device:  { host, username, password, port, secret }
                    — SSH into the device and pull 'show running-config'.
      Offline file: { config_text: "<raw IOS XE config string>" }
                    — Analyse the provided config text directly (no SSH, no Cloud ID).

    Returns: { host, n_detected, n_translatable, n_supported, n_partial,
               n_not_supported, features: [...] }
    """
    config_text = body.get("config_text")
    if config_text:
        # Offline mode: analyse the provided config text directly
        analyzer = ConfigAnalyzer(
            host="(config file)", username="", password="",
        )
        result = await analyzer.analyze_from_text(config_text)
    else:
        analyzer = ConfigAnalyzer(
            host     = body["host"],
            username = body["username"],
            password = body["password"],
            port     = body.get("port", 22),
            secret   = body.get("secret"),
        )
        result = await analyzer.analyze()

    if result.error:
        raise HTTPException(status_code=500, detail=result.error)
    return result_to_dict(result)


# ------------------------------------------------------------------ #
#  Semi-automation: service meraki connect only                        #
# ------------------------------------------------------------------ #

@app.post("/api/service-meraki-connect", tags=["Single Device"])
async def service_meraki_connect(body: dict):
    from models import DeviceRequest
    req = DeviceRequest(
        host=body["host"], username=body["username"], password=body["password"],
        port=body.get("port", 22), secret=body.get("secret"), mode=body.get("mode","device"),
    )
    checker = DeviceChecker(req)
    try:
        cloud_id = await checker.issue_service_meraki_connect()
        if cloud_id:
            return {"cloud_id": cloud_id}
        return JSONResponse(status_code=500, content={"error": "no Cloud ID returned"})
    except Exception as ex:
        return JSONResponse(status_code=500, content={"error": str(ex)})


# ------------------------------------------------------------------ #
#  Serve UI                                                            #
# ------------------------------------------------------------------ #

UI_DIR = Path(__file__).parent / "ui"

@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def serve_ui():
    """Serve the React UI. Place index.html in the ui/ subdirectory next to app.py."""
    index = UI_DIR / "index.html"
    if not index.exists():
        return HTMLResponse("<h2>UI not found — place index.html in ./ui/</h2>", status_code=404)
    return HTMLResponse(index.read_text())

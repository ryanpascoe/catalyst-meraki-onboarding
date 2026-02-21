#!/usr/bin/env python3
"""
cli.py — Command-line runner for single device or bulk onboarding.

Usage:
  Single device (SSH only):
    python cli.py --host 192.168.1.10 --user admin --password Cisco123! --mode device

  Single device + claim to Dashboard:
    python cli.py --host 192.168.1.10 --user admin --password Cisco123! --mode device \\
      --api-key YOUR_KEY --org-id 123456 --network-id L_646829496481105433

  Bulk from CSV (SSH only):
    python cli.py --csv devices.csv

  Bulk from CSV + claim to Dashboard:
    python cli.py --csv devices.csv \\
      --api-key YOUR_KEY --org-id 123456 --network-id L_646829496481105433

CSV columns: host, username, password, port, mode, secret
"""

import asyncio
import argparse
import csv
import json
from datetime import datetime

from device_checker import DeviceChecker
from bulk_orchestrator import BulkOrchestrator
from meraki_api import MerakiDashboardClient, MerakiAPIError
from models import DeviceRequest, BulkRequest

ANSI = {
    "#00e676": "\033[92m",
    "#ffd600": "\033[93m",
    "#ff4444": "\033[91m",
    "#00c8ff": "\033[96m",
    "#4a6080": "\033[90m",
    "#e0eeff": "\033[97m",
    "reset":   "\033[0m",
}

def c(msg, color):
    return f"{ANSI.get(color,'')}{msg}{ANSI['reset']}"

def hr(char="═", n=62):
    print(char * n)


class CLIWebSocket:
    """Stub WebSocket that prints to terminal."""
    async def send_json(self, data: dict):
        t = data.get("type")
        if t in ("log", "bulk_log"):
            print(c(f"  {data['msg']}", data.get("color", "")))
        elif t == "bulk_status":
            s = data["status"]
            pct = int((s["completed"] / max(s["total"], 1)) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct}%  ({s['completed']}/{s['total']})", end="", flush=True)
        elif t == "progress":
            pct = data.get("pct", 0)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct}%", end="", flush=True)
            if pct >= 100:
                print()


async def run_single(req: DeviceRequest, api_key=None, org_id=None, network_id=None, output=None):
    hr()
    print(c(f"  HOST : {req.host}:{req.port}", "#00c8ff"))
    print(f"  USER : {req.username}")
    print(c(f"  MODE : {'☁  Cloud Config' if req.mode == 'cloud' else '⚙  Device Config'}", "#e0eeff"))
    if api_key:
        print(c(f"  ORG  : {org_id}  NETWORK: {network_id}", "#4a6080"))
    hr()

    ws = CLIWebSocket()
    checker = DeviceChecker(req, ws=ws)
    result = await checker.run()
    print()

    hr("─")
    status_color = "#00e676" if result.status == "done" else "#ff4444"
    print(c(f"  STATUS   : {result.status.upper()}", status_color))
    if result.cloud_id:
        print(c(f"  CLOUD-ID : {result.cloud_id}", "#00c8ff"))
    if result.error:
        print(c(f"  ERROR    : {result.error}", "#ff4444"))
    hr("─")

    # Meraki API phase (if credentials provided and Cloud ID obtained)
    if api_key and org_id and network_id and result.cloud_id:
        print()
        print(c("  MERAKI DASHBOARD API", "#00c8ff"))
        hr("─")
        client = MerakiDashboardClient(api_key)

        ok, org_name = await client.verify_api_key(org_id)
        if not ok:
            print(c(f"  ✗ API key verification failed: {org_name}", "#ff4444"))
        else:
            print(c(f"  ✓ Org: {org_name}", "#00e676"))
            api_devices = [{
                "cloud_id": result.cloud_id,
                "mode":     req.mode,
                "username": req.username,
                "password": req.password,
                "secret":   req.secret,
            }]
            api_result = await client.full_onboard(
                org_id=org_id,
                network_id=network_id,
                devices=api_devices,
                log_fn=ws.send_json and (lambda msg, color="info": ws.send_json({"type": "log", "msg": msg, "color": color})),
            )
            if not api_result.get("errors"):
                print(c(f"  ✓ Device claimed to org and added to network {network_id}", "#00e676"))
            else:
                for err in api_result["errors"]:
                    print(c(f"  ✗ {err}", "#ff4444"))

    if output:
        with open(output, "a") as f:
            json.dump(result.model_dump(), f)
            f.write("\n")
        print(c(f"\n  Result saved to {output}", "#4a6080"))

    return result.model_dump()


async def run_bulk(devices: list[DeviceRequest], api_key=None, org_id=None, network_id=None,
                   add_atomically=False, output=None):
    hr()
    print(c(f"  BULK ONBOARDING — {len(devices)} device(s)", "#00c8ff"))
    if api_key:
        print(c(f"  ORG: {org_id}  NETWORK: {network_id}", "#4a6080"))
        print(c(f"  ATOMIC: {'yes — all or nothing' if add_atomically else 'no — best effort'}", "#4a6080"))
    hr()

    if api_key and org_id and network_id:
        req = BulkRequest(
            devices=devices,
            meraki_api_key=api_key,
            org_id=org_id,
            network_id=network_id,
            add_atomically=add_atomically,
        )
        ws = CLIWebSocket()
        orch = BulkOrchestrator(req, ws=ws)
        status = await orch.run()
        print()
        hr("─")
        print(c(f"  DONE — {status.succeeded} succeeded / {status.failed} failed / {status.total} total", "#00e676"))
        if status.meraki_claim_result:
            print(c("  ✓ Org inventory claim: OK", "#00e676"))
        if status.meraki_network_result:
            print(c("  ✓ Network assignment: OK", "#00e676"))

        if output:
            with open(output, "w") as f:
                json.dump(status.model_dump(), f, indent=2)
            print(c(f"\n  Full results saved to {output}", "#4a6080"))
        return status.model_dump()

    else:
        # SSH-only bulk (no API)
        print(c("  No Meraki API credentials — SSH checks only", "#ffd600"))
        results = []
        for dev in devices:
            result = await run_single(dev, output=None)
            results.append(result)

        done   = sum(1 for r in results if r["status"] == "done")
        failed = sum(1 for r in results if r["status"] == "failed")
        hr()
        print(c(f"  SUMMARY: {done} succeeded / {failed} failed / {len(results)} total", "#00e676"))
        hr()

        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            print(c(f"  Results saved to {output}", "#4a6080"))
        return results


def load_csv(path: str) -> list[DeviceRequest]:
    devices = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append(DeviceRequest(
                host=row["host"],
                username=row["username"],
                password=row["password"],
                port=int(row.get("port", 22)),
                mode=row.get("mode", "device"),
                secret=row.get("secret") or None,
            ))
    return devices


def main():
    parser = argparse.ArgumentParser(description="Catalyst 9K → Meraki Onboarding CLI")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--host", help="Single device IP or hostname")
    src.add_argument("--csv",  help="CSV file (host,username,password,port,mode,secret)")

    # SSH credentials (for --host)
    parser.add_argument("--user",     help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--port",     type=int, default=22)
    parser.add_argument("--mode",     choices=["device", "cloud"], default="device")
    parser.add_argument("--secret",   help="Enable/secret password")

    # Meraki Dashboard API (optional — triggers API claim after SSH)
    parser.add_argument("--api-key",    dest="api_key",    help="Meraki Dashboard API key")
    parser.add_argument("--org-id",     dest="org_id",     help="Meraki Organization ID")
    parser.add_argument("--network-id", dest="network_id", help="Meraki Network ID")
    parser.add_argument("--atomic",     action="store_true",
                        help="Add all devices or none (addAtomically=true)")

    # Output
    parser.add_argument("--output", help="Save results to JSON file")

    args = parser.parse_args()

    if args.host and (not args.user or not args.password):
        parser.error("--user and --password required with --host")

    if args.host:
        req = DeviceRequest(
            host=args.host, username=args.user, password=args.password,
            port=args.port, mode=args.mode, secret=args.secret,
        )
        asyncio.run(run_single(req, args.api_key, args.org_id, args.network_id, args.output))
    else:
        devices = load_csv(args.csv)
        asyncio.run(run_bulk(
            devices, args.api_key, args.org_id, args.network_id,
            args.atomic, args.output
        ))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Camera Fleet Manager & Scaling Orchestrator (mock-object)
Course: IT6027 - Cybersecurity Policy and Governance

Provides high-level management to scale, customize, and orchestrate diverse
IoT camera mock devices locally or generate Docker Compose configurations.
"""

import sys
import os
import time
import json
import argparse
import signal
import subprocess
from typing import List, Dict, Any

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.join(CUR_DIR, "engine")
PROFILES_DIR = os.path.join(CUR_DIR, "profiles")
STATE_FILE = os.path.join(CUR_DIR, ".fleet_state.json")

if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

from camera_server import CameraServer, load_profile

AVAILABLE_PROFILES = [
    "dlink_dcs932l",
    "hikvision_ds2cd",
    "dahua_ipc",
    "open_access_cam",
    "ip_webcam",
    "hardened_cam"
]

def get_available_profiles_info() -> List[Dict[str, Any]]:
    """Load info for all available profiles."""
    results = []
    if os.path.exists(PROFILES_DIR):
        for f in sorted(os.listdir(PROFILES_DIR)):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(PROFILES_DIR, f), "r", encoding="utf-8") as fp:
                        data = json.load(fp)
                        results.append({
                            "id": data.get("profile_id", f[:-5]),
                            "name": data.get("name"),
                            "vendor": data.get("vendor"),
                            "model": data.get("model"),
                            "auth_type": data.get("auth_type"),
                            "posture": data.get("security_posture")
                        })
                except Exception:
                    pass
    return results

def save_state(state: Dict[str, Any]):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"processes": []}

def start_fleet(count: int = 4, mixed: bool = True, use_loopback_ips: bool = True, base_http: int = 8081, base_rtsp: int = 8554):
    """Launch multiple camera mock instances in background subprocesses."""
    print("=" * 70)
    print(f"      Launching Camera Fleet ({count} instances)")
    print("=" * 70)

    state = load_state()
    active_procs = state.get("processes", [])

    profiles_to_use = AVAILABLE_PROFILES if mixed else ["dlink_dcs932l"] * count
    camera_runner = os.path.join(ENGINE_DIR, "camera_server.py")

    for i in range(count):
        prof_name = profiles_to_use[i % len(profiles_to_use)]
        prof_data = load_profile(prof_name)

        if use_loopback_ips:
            bind_ip = f"127.0.0.{2 + i}"
            http_p = prof_data.get("default_http_port", base_http + i)
            rtsp_p = prof_data.get("default_rtsp_port", base_rtsp + i)
        else:
            bind_ip = "0.0.0.0"
            http_p = base_http + i
            rtsp_p = base_rtsp + i

        cmd = [
            sys.executable,
            camera_runner,
            "--profile", prof_name,
            "--ip", bind_ip,
            "--http-port", str(http_p),
            "--rtsp-port", str(rtsp_p)
        ]

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        active_procs.append({
            "pid": proc.pid,
            "profile": prof_name,
            "ip": bind_ip,
            "http_port": http_p,
            "rtsp_port": rtsp_p,
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%S")
        })
        print(f"  [+] Spawned Node #{i+1}: {prof_name} on {bind_ip}:{http_p} / RTSP:{rtsp_p} (PID: {proc.pid})")
        time.sleep(0.3)

    state["processes"] = active_procs
    save_state(state)
    print("-" * 70)
    print(f"[+] Successfully deployed {count} camera mock nodes.")
    print("    Run 'python mock-object/fleet_manager.py list' to view status.")
    print("    Run 'python mock-object/fleet_manager.py stop' to terminate all nodes.\n")
    return active_procs

def stop_fleet():
    """Terminate all running fleet subprocesses."""
    state = load_state()
    procs = state.get("processes", [])
    if not procs:
        print("[i] No fleet instances currently recorded.")
        return

    print(f"[*] Terminating {len(procs)} mock camera instances...")
    for p in procs:
        pid = p.get("pid")
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"  [-] Stopped PID {pid} ({p.get('profile')} on port {p.get('http_port')})")
        except ProcessLookupError:
            pass
        except Exception as e:
            try:
                # Windows fallback
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    if os.path.exists(STATE_FILE):
        try:
            os.remove(STATE_FILE)
        except Exception:
            pass
    print("[+] All fleet instances stopped.")
    return len(procs)

def list_fleet():
    """Display active fleet instances."""
    state = load_state()
    procs = state.get("processes", [])
    print("=" * 70)
    print(f"{'ACTIVE CAMERA FLEET NODES':^70}")
    print("=" * 70)
    if not procs:
        print("  No camera instances running currently.")
    else:
        print(f"  {'PID':<8} {'Profile':<20} {'HTTP Port':<12} {'RTSP Port':<12} {'Started'}")
        print("  " + "-" * 66)
        for p in procs:
            print(f"  {p.get('pid'):<8} {p.get('profile'):<20} {p.get('http_port'):<12} {p.get('rtsp_port'):<12} {p.get('start_time')}")
    print("-" * 70)

def generate_compose(count: int = 3, output_path: str = None):
    """Generate a multi-camera Docker Compose file for large-scale tests."""
    lines = [
        "version: '3.8'",
        "",
        "# Auto-generated Camera Fleet Compose Stack",
        "networks:",
        "  vlan10_standard_iot:",
        "    name: iot_vlan10_standard",
        "    driver: bridge",
        "    ipam:",
        "      driver: default",
        "      config:",
        "        - subnet: 172.28.10.0/24",
        "          gateway: 172.28.10.1",
        "",
        "services:"
    ]

    profiles = AVAILABLE_PROFILES
    for i in range(count):
        prof = profiles[i % len(profiles)]
        svc_name = f"mock-camera-{i+1:02d}"
        ip = f"172.28.10.{20 + i}"
        lines.extend([
            f"  {svc_name}:",
            f"    build:",
            f"      context: .",
            f"      dockerfile: templates/camera-mock/Dockerfile",
            f"    image: iot-mock-camera:latest",
            f"    container_name: {svc_name}",
            f"    hostname: {prof.replace('_', '-')}-{i+1:02d}",
            f"    environment:",
            f"      - CAMERA_PROFILE={prof}",
            f"      - MOCK_IP={ip}",
            f"    networks:",
            f"      vlan10_standard_iot:",
            f"        ipv4_address: {ip}",
            f"    restart: unless-stopped",
            ""
        ])

    content = "\n".join(lines)
    target = output_path or os.path.join(CUR_DIR, "docker-compose.template.yml")
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Generated Docker Compose with {count} camera nodes at: {target}")

def main():
    parser = argparse.ArgumentParser(description="Camera Fleet Manager & Scaling Orchestrator")
    subparsers = parser.add_subparsers(dest="command", help="Fleet commands")

    # start-fleet
    sp_start = subparsers.add_parser("start-fleet", help="Start N camera mock instances")
    sp_start.add_argument("--count", type=int, default=3, help="Number of cameras to launch")
    sp_start.add_argument("--mixed", action="store_true", default=True, help="Use diverse camera profiles")
    sp_start.add_argument("--base-http", type=int, default=8080, help="Base HTTP port (default: 8080)")
    sp_start.add_argument("--base-rtsp", type=int, default=8554, help="Base RTSP port (default: 8554)")

    # stop-fleet / stop
    subparsers.add_parser("stop-fleet", help="Stop all running camera fleet instances")
    subparsers.add_parser("stop", help="Stop all running camera fleet instances (alias)")

    # list
    subparsers.add_parser("list", help="List active fleet instances")

    # profiles
    subparsers.add_parser("profiles", help="List available camera profiles")

    # generate-compose
    sp_gen = subparsers.add_parser("generate-compose", help="Generate scaled Docker Compose file")
    sp_gen.add_argument("--count", type=int, default=4, help="Number of camera containers")
    sp_gen.add_argument("--out", type=str, default=None, help="Output file path")

    args = parser.parse_args()

    if args.command == "start-fleet":
        start_fleet(count=args.count, mixed=args.mixed, base_http=args.base_http, base_rtsp=args.base_rtsp)
    elif args.command in ["stop-fleet", "stop"]:
        stop_fleet()
    elif args.command == "list":
        list_fleet()
    elif args.command == "profiles":
        print("=" * 70)
        print(f"{'AVAILABLE CAMERA PROFILES':^70}")
        print("=" * 70)
        for p in get_available_profiles_info():
            print(f"  * [{p['id']}] {p['name']}")
            print(f"    Vendor: {p['vendor']} | Model: {p['model']} | Auth: {p['auth_type']}")
            print(f"    Posture: {p['posture']}\n")
    elif args.command == "generate-compose":
        generate_compose(count=args.count, output_path=args.out)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

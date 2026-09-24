#!/usr/bin/env python3
"""
IoT Core Gateway & Telemetry Registry (net-core)
Provides central IoT device registration, telemetry ingestion via MQTT and HTTP REST,
and real-time status visibility for all edge IoT devices (including smartphones).
"""

import sys
import json
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# In-memory IoT device registry
REGISTRY_LOCK = threading.Lock()
CONNECTED_DEVICES = {}

def register_telemetry(device_id, dev_type, payload, source_ip="unknown"):
    """Update or register an IoT device with incoming telemetry."""
    now = datetime.now().isoformat()
    with REGISTRY_LOCK:
        if device_id not in CONNECTED_DEVICES:
            CONNECTED_DEVICES[device_id] = {
                "device_id": device_id,
                "device_type": dev_type,
                "first_seen": now,
                "source_ip": source_ip,
                "telemetry_count": 0,
                "latest_telemetry": {},
                "history": []
            }
        dev = CONNECTED_DEVICES[device_id]
        dev["last_seen"] = now
        dev["source_ip"] = source_ip if source_ip != "unknown" else dev.get("source_ip", "unknown")
        dev["telemetry_count"] += 1
        dev["latest_telemetry"] = payload
        # Keep last 10 telemetry events
        dev["history"].append({"timestamp": now, "payload": payload})
        if len(dev["history"]) > 10:
            dev["history"].pop(0)

class IoTGatewayHTTPHandler(BaseHTTPRequestHandler):
    """HTTP REST handler for device telemetry and web status."""

    def _send_json(self, status_code, data):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/status":
            with REGISTRY_LOCK:
                devices_summary = [
                    {
                        "device_id": d["device_id"],
                        "device_type": d["device_type"],
                        "source_ip": d["source_ip"],
                        "last_seen": d["last_seen"],
                        "telemetry_count": d["telemetry_count"],
                        "latest": d["latest_telemetry"]
                    }
                    for d in CONNECTED_DEVICES.values()
                ]
            self._send_json(200, {
                "system": "IoT Core Gateway",
                "status": "OPERATIONAL",
                "active_device_count": len(devices_summary),
                "devices": devices_summary,
                "endpoints": {
                    "POST /api/telemetry": "Ingest device telemetry (JSON: device_id, type, data)",
                    "GET /api/devices": "List full registered device details",
                    "GET /status": "Summary health and active devices"
                }
            })
        elif parsed.path == "/api/devices":
            with REGISTRY_LOCK:
                self._send_json(200, list(CONNECTED_DEVICES.values()))
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/telemetry":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_json(400, {"error": "Missing payload"})
                return
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode("utf-8"))
                device_id = str(data.get("device_id", "unnamed_device"))
                dev_type = str(data.get("type", "generic_sensor"))
                payload = data.get("data", data)
                client_ip = self.client_address[0]
                register_telemetry(device_id, dev_type, payload, source_ip=client_ip)
                print(f"[+] [HTTP Ingestion] Telemetry from {device_id} ({client_ip}): {payload}")
                self._send_json(200, {"status": "success", "device_id": device_id})
            except Exception as e:
                self._send_json(400, {"error": f"Invalid JSON: {str(e)}"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        # Suppress verbose standard HTTP server logging
        return

def start_mqtt_listener(broker_host="localhost", broker_port=1883):
    """Optional background listener for Mosquitto MQTT broker."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("[i] Note: paho-mqtt not available or not installed. Running in HTTP-only ingestion mode.")
        return

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[+] [MQTT Listener] Successfully connected to broker at {broker_host}:{broker_port}")
            client.subscribe("iot/#")
        else:
            print(f"[!] [MQTT Listener] Connection failed with code {rc}")

    def on_message(client, userdata, msg):
        topic = msg.topic
        payload_str = msg.payload.decode("utf-8", errors="ignore")
        try:
            payload = json.loads(payload_str)
        except Exception:
            payload = {"raw": payload_str}
        # Derive device ID from topic, e.g. iot/sensors/livingroom/temperature -> livingroom
        parts = topic.strip("/").split("/")
        dev_id = parts[2] if len(parts) >= 3 else parts[-1]
        dev_type = parts[1] if len(parts) >= 2 else "mqtt_device"
        register_telemetry(dev_id, dev_type, payload, source_ip="mqtt_broker")
        print(f"[+] [MQTT Ingestion] {topic} -> {payload}")

    try:
        # Paho MQTT 2.x compatibility
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="iot-core-gateway")
        except AttributeError:
            client = mqtt.Client(client_id="iot-core-gateway")
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect_async(broker_host, broker_port, 60)
        client.loop_start()
    except Exception as e:
        print(f"[i] MQTT listener failed to start (broker may not be running yet): {e}")

def run_gateway(host="0.0.0.0", port=5000):
    print("=" * 65)
    print("         IoT Core Gateway - Central Hub & Telemetry Registry   ")
    print("=" * 65)
    print(f"[*] Starting HTTP Telemetry Gateway on http://{host}:{port}")
    
    # Start MQTT background thread
    mqtt_thread = threading.Thread(target=start_mqtt_listener, daemon=True)
    mqtt_thread.start()

    server = HTTPServer((host, port), IoTGatewayHTTPHandler)
    print(f"[+] Ready to receive telemetry from smartphones & IoT devices.")
    print(f"    - Endpoint: http://{host}:{port}/api/telemetry")
    print(f"    - Status:   http://{host}:{port}/status\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down IoT Gateway.")
        server.server_close()

if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_gateway(port=port)

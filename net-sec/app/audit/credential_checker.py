"""
Default Credential Auditing Engine (net-sec)
Non-destructively tests discovered IoT endpoints against a predefined list of
publicly known default usernames and passwords (mandatory course requirement).
"""

import os
import socket
import base64
import time
import httpx
from typing import List, Dict, Tuple, Any

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "default_passwords.txt")

def load_default_credentials() -> List[Tuple[str, str]]:
    creds = []
    if not os.path.exists(WORDLIST_PATH):
        return [("admin", "admin"), ("root", "root"), ("admin", "123456"), ("root", "xc3511")]
    with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pwd = line.split(":", 1)
                creds.append((user.strip(), pwd.strip()))
    return creds

def test_http_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 0.8) -> Dict[str, Any]:
    """Test HTTP Basic / Digest authentication and detect unauthenticated open access."""
    url = f"http://{ip}:{port}/"
    try:
        # Initial probe to check if authentication is requested
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            
            # If 200 OK without any credentials, sensitive IoT endpoints (e.g. cameras) are completely open!
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                # Check for camera streaming, device controls, or unauthenticated management consoles
                is_sensitive_open = any(kw in body_lower for kw in [
                    "ip webcam", "camera", "video", "stream", "live", "h.264", "relay",
                    "switch", "control", "admin", "login", "configuration", "settings",
                    "gateway", "router", "sensor", "telemetry"
                ]) or port in [80, 8080, 8081, 5000, 8089, 9999]
                
                if is_sensitive_open:
                    return {
                        "auth_required": False,
                        "matched_credential": "<NONE> (Open Access / No Password)",
                        "service": f"HTTP ({port})",
                        "is_open_access": True,
                        "description": f"Critical Security Violation: Port {port} does not require authentication. Sensitive device services / streams are completely open."
                    }
                return {"auth_required": False, "matched_credential": None, "is_open_access": False}

            if resp.status_code != 401:
                return {"auth_required": False, "matched_credential": None, "is_open_access": False}
            
            # 401 returned, proceed to test against predefined dictionary
            for user, pwd in creds:
                auth_resp = client.get(url, auth=(user, pwd))
                if auth_resp.status_code in [200, 301, 302]:
                    return {
                        "auth_required": True,
                        "matched_credential": f"{user}:{pwd}",
                        "service": "HTTP Basic/Digest",
                        "is_open_access": False,
                        "description": f"Publicly known default credential found on port {port}: {user}:{pwd}"
                    }
    except Exception:
        pass
    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

def test_telnet_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 1.0) -> Dict[str, Any]:
    """Test Telnet authentication against default credentials (e.g. Mirai dictionary)."""
    for user, pwd in creds:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            # Read banner and login prompt
            data = sock.recv(1024).decode("utf-8", errors="ignore")
            if "login" in data.lower() or "username" in data.lower():
                sock.sendall((user + "\r\n").encode("utf-8"))
                time.sleep(0.1)
                sock.recv(1024)
                sock.sendall((pwd + "\r\n").encode("utf-8"))
                time.sleep(0.2)
                res = sock.recv(1024).decode("utf-8", errors="ignore")
                
                # Check for successful shell prompt (#, $, >) and lack of error
                if ("#" in res or "$" in res or ">" in res) and "incorrect" not in res.lower() and "failed" not in res.lower():
                    sock.close()
                    return {
                        "auth_required": True,
                        "matched_credential": f"{user}:{pwd}",
                        "service": "Telnet"
                    }
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return {"auth_required": True, "matched_credential": None}

def test_device_credentials(ip: str, open_ports: List[int]) -> Dict[str, Any]:
    """Audit all open services on an IoT device against the predefined dictionary."""
    creds = load_default_credentials()
    results = {
        "vulnerable": False,
        "findings": []
    }

    # Test HTTP ports
    for p in open_ports:
        if p in [80, 443, 8080, 8081, 8089, 5000, 9999] or (p not in [21, 22, 23, 1883]):
            res = test_http_auth(ip, p, creds)
            if res.get("matched_credential"):
                results["vulnerable"] = True
                results["findings"].append({
                    "port": p,
                    "service": res.get("service", f"HTTP ({p})"),
                    "credential": res["matched_credential"],
                    "is_open_access": res.get("is_open_access", False),
                    "description": res.get("description", f"Publicly known default credential found on port {p}")
                })
                break  # Stop on first finding per port class

    # Test Telnet
    if 23 in open_ports:
        telnet_res = test_telnet_auth(ip, 23, creds)
        if telnet_res.get("matched_credential"):
            results["vulnerable"] = True
            results["findings"].append({
                "port": 23,
                "service": "Telnet (23)",
                "credential": telnet_res["matched_credential"],
                "description": "Mirai-susceptible default password confirmed on Telnet"
            })

    return results

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"[*] Testing default credentials on {target}...")
    res = test_device_credentials(target, [8080, 23])
    print(f"[+] Result: {res}")

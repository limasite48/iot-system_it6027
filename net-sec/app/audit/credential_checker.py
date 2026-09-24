"""
Default Credential & Authentication Auditing Engine (net-sec)
Non-destructively audits discovered IoT endpoints against predefined default credentials
and identifies unauthenticated open-access services (cameras, dashboards, control panels).
Supports HTTP Basic Auth, HTTP Digest Auth (Android IP Webcam), and Web Form Auth.
"""

import os
import re
import socket
import base64
import time
import httpx
from typing import List, Dict, Tuple, Any, Optional

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "default_passwords.txt")

def load_default_credentials() -> List[Tuple[str, str]]:
    """Load default username:password combinations from dictionary."""
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

def test_http_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 2.5) -> Dict[str, Any]:
    """
    Test an HTTP/HTTPS service for unauthenticated open access or default credentials.
    Dynamically supports:
      1. HTTP Digest Authentication (RFC 7616 / Android IP Webcam)
      2. HTTP Basic Authentication (RFC 7617 / Embedded cameras, routers)
      3. Unauthenticated Open Access (Zero password protection on service endpoint)
    """
    schemes = ["http"]
    if port == 443:
        schemes = ["https"]
    elif port in [8443, 4443]:
        schemes = ["https", "http"]
    else:
        schemes = ["http", "https"]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*"
    }

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/"
        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                
                # Case 1: Endpoint returns 200 OK without requiring authentication
                if resp.status_code == 200:
                    # Check whether this is a web login form that requires entering a password
                    has_login_form = bool(
                        re.search(r'<input[^>]+type=[\'"]password[\'"]', resp.text, re.IGNORECASE) or
                        re.search(r'<input[^>]+name=[\'"](password|pwd|pass|key)[\'"]', resp.text, re.IGNORECASE)
                    )
                    
                    if has_login_form:
                        # Form-based login required: test default credentials via POST
                        for user, pwd in creds:
                            try:
                                post_data = {"username": user, "password": pwd, "user": user, "pass": pwd}
                                post_resp = client.post(url, data=post_data, headers=headers)
                                if post_resp.status_code in [200, 301, 302, 307] and "invalid" not in post_resp.text.lower():
                                    return {
                                        "auth_required": True,
                                        "matched_credential": f"{user}:{pwd}",
                                        "service": f"Web Form ({port})",
                                        "is_open_access": False,
                                        "description": f"Default credential confirmed via Web Login Form on port {port}: {user}:{pwd}"
                                    }
                            except Exception:
                                pass
                        return {"auth_required": True, "matched_credential": None, "is_open_access": False}
                    
                    # No login form and no authentication requested: Service is OPEN ACCESS
                    return {
                        "auth_required": False,
                        "matched_credential": "<NONE> (Open Access / No Password Required)",
                        "service": f"HTTP ({port})",
                        "is_open_access": True,
                        "description": f"Critical Security Violation: Port {port} grants open access without requiring any password or authentication."
                    }

                # Case 2: Endpoint challenges for HTTP authentication (401 or 403)
                if resp.status_code in [401, 403]:
                    auth_header = resp.headers.get("WWW-Authenticate", "")
                    is_digest = "digest" in auth_header.lower()

                    for user, pwd in creds:
                        # 1. Primary authentication check (Digest or Basic depending on server challenge)
                        if is_digest:
                            auth_handler = httpx.DigestAuth(user, pwd)
                            svc_name = f"HTTP Digest ({port})"
                        else:
                            auth_handler = httpx.BasicAuth(user, pwd)
                            svc_name = f"HTTP Basic ({port})"

                        try:
                            auth_resp = client.get(url, auth=auth_handler, headers=headers)
                            if auth_resp.status_code in [200, 301, 302, 307]:
                                return {
                                    "auth_required": True,
                                    "matched_credential": f"{user}:{pwd}",
                                    "service": svc_name,
                                    "is_open_access": False,
                                    "description": f"Publicly known default credential accepted on port {port}: {user}:{pwd}"
                                }

                            # 2. Fallback: try DigestAuth if Basic returned 401
                            if not is_digest and auth_resp.status_code == 401:
                                auth_resp_digest = client.get(url, auth=httpx.DigestAuth(user, pwd), headers=headers)
                                if auth_resp_digest.status_code in [200, 301, 302, 307]:
                                    return {
                                        "auth_required": True,
                                        "matched_credential": f"{user}:{pwd}",
                                        "service": f"HTTP Digest ({port})",
                                        "is_open_access": False,
                                        "description": f"Publicly known default credential accepted on port {port}: {user}:{pwd}"
                                    }
                        except Exception:
                            continue

                    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

        except Exception:
            continue

    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

def test_rtsp_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 2.0) -> Dict[str, Any]:
    """Test RTSP streaming endpoint (port 554) for open access or default credentials."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        req = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        res = sock.recv(2048).decode("utf-8", errors="ignore")
        sock.close()

        if "RTSP/1.0 200" in res:
            return {
                "auth_required": False,
                "matched_credential": "<NONE> (Open RTSP Stream)",
                "service": f"RTSP ({port})",
                "is_open_access": True,
                "description": f"Critical Security Violation: RTSP camera feed on port {port} has no authentication required."
            }

        if "RTSP/1.0 401" in res:
            for user, pwd in creds[:5]: # Check top default credentials
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                sock_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_auth.settimeout(timeout)
                sock_auth.connect((ip, port))
                req_auth = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {token}\r\n\r\n"
                sock_auth.sendall(req_auth.encode("utf-8"))
                res_auth = sock_auth.recv(2048).decode("utf-8", errors="ignore")
                sock_auth.close()
                if "RTSP/1.0 200" in res_auth:
                    return {
                        "auth_required": True,
                        "matched_credential": f"{user}:{pwd}",
                        "service": f"RTSP ({port})",
                        "is_open_access": False,
                        "description": f"Default credential confirmed on RTSP port {port}: {user}:{pwd}"
                    }
    except Exception:
        pass
    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

def test_telnet_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 1.5) -> Dict[str, Any]:
    """Test Telnet authentication against default credentials (e.g. Mirai dictionary)."""
    for user, pwd in creds:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            data = sock.recv(1024).decode("utf-8", errors="ignore")
            if "login" in data.lower() or "username" in data.lower():
                sock.sendall((user + "\r\n").encode("utf-8"))
                time.sleep(0.1)
                sock.recv(1024)
                sock.sendall((pwd + "\r\n").encode("utf-8"))
                time.sleep(0.2)
                res = sock.recv(1024).decode("utf-8", errors="ignore")
                
                if ("#" in res or "$" in res or ">" in res) and "incorrect" not in res.lower() and "failed" not in res.lower():
                    sock.close()
                    return {
                        "auth_required": True,
                        "matched_credential": f"{user}:{pwd}",
                        "service": f"Telnet ({port})",
                        "is_open_access": False,
                        "description": f"Mirai-susceptible default password confirmed on Telnet port {port}: {user}:{pwd}"
                    }
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

def test_device_credentials(ip: str, open_ports: List[int]) -> Dict[str, Any]:
    """
    Audit all discovered services on an IoT device against the predefined dictionary
    and check for unauthenticated open access.
    """
    creds = load_default_credentials()
    results = {
        "vulnerable": False,
        "findings": []
    }

    # Deduplicate and sort open ports
    ports_to_test = sorted(list(set(open_ports)))

    for p in ports_to_test:
        res = None
        # 1. Telnet
        if p == 23:
            res = test_telnet_auth(ip, p, creds)
        # 2. RTSP Video Streaming
        elif p == 554:
            res = test_rtsp_auth(ip, p, creds)
        # 3. HTTP / HTTPS and Web services (Port 80, 8080, 8081, 5000, 9999, etc.)
        elif p not in [21, 22, 1883]:
            res = test_http_auth(ip, p, creds)

        if res and res.get("matched_credential"):
            results["vulnerable"] = True
            results["findings"].append({
                "port": p,
                "service": res.get("service", f"Port {p}"),
                "credential": res["matched_credential"],
                "is_open_access": res.get("is_open_access", False),
                "description": res.get("description", f"Credential finding on port {p}")
            })

    return results

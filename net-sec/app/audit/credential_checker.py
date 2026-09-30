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

def is_sensitive_iot_service(port: int, body_text: str, content_type: str = "") -> bool:
    """
    Determine if an unauthenticated HTTP service exposes sensitive IoT capabilities
    (video streams, physical actuator controls, device configuration panels).
    """
    text_lower = body_text.lower()
    ct_lower = content_type.lower()

    # 1. Video / Camera streaming surfaces (IP Webcam, MJPEG, RTSP-over-HTTP)
    if "multipart/x-mixed-replace" in ct_lower or "video/" in ct_lower:
        return True
    if any(cam in text_lower for cam in [
        "ip webcam", "webcam", "live video", "live stream", "video stream",
        "mjpeg", "h.264", "camera feed", "surveillance", "snapshot.jpg", "videostream.cgi"
    ]):
        return True

    # 2. Smart Plug / IoT relay actuator switches (TP-Link, WeMo, Sonoff, Shelly)
    if any(plug in text_lower for plug in [
        "smart plug", "smart switch", "relay", "toggle", "power switch",
        "wemo switch", "hs100", "hs110", "kasa", '"voltage":', '"state":', '"relay":'
    ]):
        return True

    # 3. Embedded DVR / gateway administration panel
    if any(dvr in text_lower for dvr in ["uc-httpd", "xiongmai", "busybox", "net surveillance system", "h.264 dvr"]):
        return True

    # 4. Standard camera / plug ports with active streaming/control content
    if port in [8080, 8081, 8089, 8888, 9999]:
        if any(term in text_lower for term in ["stream", "camera", "video", "control", "status", "switch", "device"]):
            return True

    return False

def test_http_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 2.5) -> Dict[str, Any]:
    """
    Test an HTTP/HTTPS service for unauthenticated open access or default credentials.
    Dynamically supports:
      1. HTTP Digest Authentication (RFC 7616 / Android IP Webcam)
      2. HTTP Basic Authentication (RFC 7617 / Embedded cameras, routers)
      3. Web Form-based Authentication (without false-positives)
      4. Targeted Unauthenticated Open Access on sensitive IoT endpoints
    """
    schemes = ["http"]
    if port in [443, 8443]:
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
                        # Extract target post URL from form action if present
                        action_match = re.search(r'<form[^>]+action=[\'"]([^\'"]*)[\'"]', resp.text, re.IGNORECASE)
                        post_url = url
                        if action_match and action_match.group(1).strip():
                            act = action_match.group(1).strip()
                            if act.startswith("http://") or act.startswith("https://"):
                                post_url = act
                            elif act.startswith("/"):
                                post_url = f"{scheme}://{ip}:{port}{act}"
                            else:
                                post_url = f"{url.rstrip('/')}/{act}"

                        for user, pwd in creds:
                            try:
                                post_data = {"username": user, "password": pwd, "user": user, "pass": pwd, "login": user}
                                post_resp = client.post(post_url, data=post_data, headers=headers, follow_redirects=False)

                                is_redirect_success = False
                                if post_resp.status_code in [301, 302, 303, 307]:
                                    loc = post_resp.headers.get("Location", "").lower()
                                    if loc and not any(fail_word in loc for fail_word in ["login", "signin", "auth", "error"]):
                                        is_redirect_success = True
                                    elif post_resp.headers.get("Set-Cookie"):
                                        is_redirect_success = True

                                is_200_success = False
                                if post_resp.status_code == 200:
                                    still_has_pw = bool(
                                        re.search(r'<input[^>]+type=[\'"]password[\'"]', post_resp.text, re.IGNORECASE)
                                    )
                                    has_fail_msg = any(f in post_resp.text.lower() for f in [
                                        "invalid", "failed", "incorrect", "wrong username", "wrong password",
                                        "authentication failure", "access denied", "bad password", "not authorized",
                                        "login error", "unauthorized"
                                    ])
                                    has_auth_cookie = bool(post_resp.headers.get("Set-Cookie"))
                                    if (not still_has_pw or has_auth_cookie) and not has_fail_msg:
                                        is_200_success = True

                                if is_redirect_success or is_200_success:
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

                    # No login form: Check if this service exposes sensitive IoT functionality without auth
                    ct = resp.headers.get("Content-Type", "")
                    if is_sensitive_iot_service(port, resp.text, ct):
                        return {
                            "auth_required": False,
                            "matched_credential": "<NONE> (Open Access / No Password Required)",
                            "service": f"HTTP ({port})",
                            "is_open_access": True,
                            "description": f"Critical Security Violation: Port {port} grants open access to sensitive IoT functionality without requiring any authentication."
                        }

                    # Non-sensitive benign HTTP service
                    return {"auth_required": False, "matched_credential": None, "is_open_access": False}

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

                            # 2. Fallback: only if WWW-Authenticate did not explicitly request Basic
                            if not is_digest and "basic" not in auth_header.lower() and auth_resp.status_code == 401:
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

def test_rtsp_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 1.5) -> Dict[str, Any]:
    """Test RTSP streaming endpoint (port 554) for open access or default credentials (Basic & Digest)."""
    import hashlib
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
            # Check if server challenges with Digest or Basic
            realm_match = re.search(r'realm="([^"]+)"', res, re.IGNORECASE)
            nonce_match = re.search(r'nonce="([^"]+)"', res, re.IGNORECASE)
            is_digest = "digest" in res.lower() and realm_match and nonce_match
            realm = realm_match.group(1) if realm_match else "IPCamera"
            nonce = nonce_match.group(1) if nonce_match else ""

            for user, pwd in creds:
                try:
                    sock_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock_auth.settimeout(timeout)
                    sock_auth.connect((ip, port))

                    if is_digest:
                        ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
                        ha2 = hashlib.md5(f"DESCRIBE:rtsp://{ip}:{port}/live".encode()).hexdigest()
                        resp_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                        auth_header = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="rtsp://{ip}:{port}/live", response="{resp_hash}"'
                    else:
                        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        auth_header = f"Basic {token}"

                    req_auth = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\nCSeq: 2\r\nAuthorization: {auth_header}\r\n\r\n"
                    sock_auth.sendall(req_auth.encode("utf-8"))
                    res_auth = sock_auth.recv(2048).decode("utf-8", errors="ignore")
                    sock_auth.close()

                    if "RTSP/1.0 200" in res_auth:
                        auth_type = "Digest" if is_digest else "Basic"
                        return {
                            "auth_required": True,
                            "matched_credential": f"{user}:{pwd}",
                            "service": f"RTSP {auth_type} ({port})",
                            "is_open_access": False,
                            "description": f"Default credential confirmed on RTSP port {port}: {user}:{pwd}"
                        }
                except Exception:
                    continue
    except Exception:
        pass
    return {"auth_required": True, "matched_credential": None, "is_open_access": False}

def test_telnet_auth(ip: str, port: int, creds: List[Tuple[str, str]], timeout: float = 1.0) -> Dict[str, Any]:
    """Test Telnet authentication against default credentials (e.g. Mirai dictionary)."""
    # Quick probe: verify port is reachable
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(timeout)
        probe.connect((ip, port))
        probe.close()
    except Exception:
        return {"auth_required": True, "matched_credential": None, "is_open_access": False}

    for user, pwd in creds:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            data = sock.recv(1024).decode("utf-8", errors="ignore")
            if "login" in data.lower() or "username" in data.lower():
                sock.sendall((user + "\r\n").encode("utf-8"))
                time.sleep(0.05)
                sock.recv(1024)
                sock.sendall((pwd + "\r\n").encode("utf-8"))
                time.sleep(0.1)
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

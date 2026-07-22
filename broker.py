#!/usr/bin/env python3
"""
Simple AgileBot Device-Code Broker
==================================
Minimal broker for local pairing. No auth, no CORS restrictions.
Just mint -> deposit -> exchange.
"""
import json
import os
import re
import secrets
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BACKEND = os.environ.get("BACKEND", "https://api.agilebot.dev")
TTL = int(os.environ.get("BROKER_TTL", "300"))

lock = threading.Lock()
STORE = {}  # code -> {deposit_secret, token, user_id, expires, status}

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_RE = re.compile(r"^[A-Z0-9]{8}$")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _gen_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def _backend_me(token):
    if not token:
        return (401, None)
    target = BACKEND.rstrip("/") + "/me"
    req = urllib.request.Request(target, headers={
        "Authorization": "Bearer " + token,
        "User-Agent": UA,
    }, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        uid = data.get("id") or data.get("user_id") or data.get("sub")
        return (resp.status, uid)
    except urllib.error.HTTPError as e:
        return (e.code, None)
    except Exception:
        return (502, None)


class BrokerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parsed.query

        if path == "/health":
            self._send_json(200, {"ok": True})
            return

        if path == "/":
            self._send_json(200, {"service": "AgileBot Broker", "endpoints": ["/health", "/device-code/mint", "/device-code", "/device-code/exchange"]})
            return

        # Local mocks for the frontend's /api/* pollers that do NOT exist on the
        # real backend (api.agilebot.dev has NO /api prefix). These are non-critical
        # frontend pollers (pending-tool check, new-conversation check, heartbeat).
        if path.startswith("/api/"):
            clean = path.rstrip("/")
            if clean == "/api/pending":
                self._send_json(200, {"pending": [], "tool_requests": []})
                return
            if clean == "/api/new-conversation":
                self._send_json(200, {"id": None, "created": False})
                return
            if clean == "/api/heartbeat":
                self._send_json(200, {"ok": True})
                return
            # unknown /api route -> fall through to backend proxy below

        # proxy: forward to backend
        if path.startswith("/proxy"):
            proxy_path = path[len("/proxy"):] or "/"
            target = BACKEND.rstrip("/") + proxy_path
            if qs:
                target += "?" + qs
            auth = self.headers.get("Authorization", "")
            fwd = {
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "X-AgileBot-Client-Version": self.headers.get("X-AgileBot-Client-Version", "0.2.4"),
                "User-Agent": UA,
            }
            if auth:
                fwd["Authorization"] = auth
            req = urllib.request.Request(target, headers=fwd, method="GET")
            status, resp_body = 502, b'{"error": "backend proxy failure"}'
            try:
                resp = urllib.request.urlopen(req, timeout=30)
                status = resp.status
                resp_body = resp.read()
            except urllib.error.HTTPError as e:
                status = e.code
                resp_body = e.read() or b""
            except Exception as e:
                status = 502
                resp_body = json.dumps({"error": "backend proxy failure", "detail": str(e)}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
            self.end_headers()
            self.wfile.write(resp_body)
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parsed.query
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        # mint: plugin gets a code + deposit_secret
        if path == "/device-code/mint":
            code = _gen_code()
            dep = secrets.token_hex(16)
            with lock:
                STORE[code] = {
                    "deposit_secret": dep,
                    "token": None,
                    "user_id": None,
                    "expires": time.time() + TTL,
                    "status": "minted",
                }
            self._send_json(200, {"code": code, "deposit_secret": dep, "ttl": TTL})
            return

        # deposit: plugin stores its API token, bound to account id
        if path == "/device-code":
            code = (data.get("code") or "").upper()
            dep = data.get("deposit_secret")
            token = data.get("token")
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"})
                return
            if not isinstance(dep, str) or not dep or not isinstance(token, str) or not token:
                self._send_json(400, {"error": "deposit_secret and token required"})
                return
            with lock:
                entry = STORE.get(code)
                if not entry or entry["status"] != "minted":
                    self._send_json(409, {"error": "code not minted or already used"})
                    return
                if not secrets.compare_digest(dep, entry["deposit_secret"]):
                    self._send_json(403, {"error": "bad deposit_secret"})
                    return
            st, uid = _backend_me(token)
            if st != 200 or not uid:
                self._send_json(401, {"error": "token rejected by backend"})
                return
            with lock:
                entry["token"] = token
                entry["user_id"] = uid
                entry["status"] = "deposited"
            print(f"[broker] deposited token for code {code} (acct {uid})", flush=True)
            self._send_json(200, {"ok": True, "ttl": TTL})
            return

        # exchange: site redeems, only for the SAME account
        if path == "/device-code/exchange":
            code = (data.get("code") or "").upper()
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"})
                return
            site_auth = self.headers.get("Authorization", "")
            if site_auth.startswith("Bearer "):
                site_token = site_auth[7:]
            else:
                site_token = site_auth
            if not site_token:
                self._send_json(401, {"error": "site Authorization required"})
                return
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"error": "Code not found"})
                    return
                entry = STORE[code]
                if now > entry["expires"]:
                    del STORE[code]
                    self._send_json(410, {"error": "Code expired"})
                    return
                if entry["status"] != "deposited":
                    self._send_json(409, {"error": "code not yet deposited"})
                    return
                dep_uid = entry["user_id"]
                token = entry["token"]
            st, site_uid = _backend_me(site_token)
            if st != 200 or not site_uid:
                self._send_json(401, {"error": "site token rejected by backend"})
                return
            if site_uid != dep_uid:
                self._send_json(403, {"error": "account mismatch"})
                return
            with lock:
                del STORE[code]
            self._send_json(200, {"token": token})
            return

        # proxy: forward to backend
        if path.startswith("/proxy"):
            proxy_path = path[len("/proxy"):] or "/"
            target = BACKEND.rstrip("/") + proxy_path
            if qs:
                target += "?" + qs
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b""
            auth = self.headers.get("Authorization", "")
            fwd = {
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "X-AgileBot-Client-Version": self.headers.get("X-AgileBot-Client-Version", "0.2.4"),
                "User-Agent": UA,
            }
            if auth:
                fwd["Authorization"] = auth
            method = self.command
            req = urllib.request.Request(target, data=body if method in ("POST", "PUT", "DELETE") else None,
                                         headers=fwd, method=method)
            status, resp_body = 502, b'{"error": "backend proxy failure"}'
            try:
                resp = urllib.request.urlopen(req, timeout=30)
                status = resp.status
                resp_body = resp.read()
            except urllib.error.HTTPError as e:
                status = e.code
                resp_body = e.read() or b""
            except Exception as e:
                status = 502
                resp_body = json.dumps({"error": "backend proxy failure", "detail": str(e)}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
            self.end_headers()
            self.wfile.write(resp_body)
            return

        self._send_json(404, {"error": "Not found"})


def clean_expired_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with lock:
            expired = [k for k, v in STORE.items() if now > v["expires"]]
            for k in expired:
                del STORE[k]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "9000")))
    args = ap.parse_args()

    threading.Thread(target=clean_expired_loop, daemon=True).start()
    print(f"[broker] simple broker on http://{args.host}:{args.port} (TTL={TTL}s, backend={BACKEND})", flush=True)

    server = ThreadingHTTPServer((args.host, args.port), BrokerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down broker.", flush=True)


if __name__ == "__main__":
    main()

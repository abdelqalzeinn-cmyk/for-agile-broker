#!/usr/bin/env python3
"""
AgileBot Device-Code Broker (HARDENED)
=====================================
Security-maximized device-code pairing relay + constrained API proxy.

Trust model
-----------
- All state-changing / sensitive routes require a shared BROKER_KEY
  (X-Broker-Key header). Missing or wrong key -> 401. Fail-closed: the broker
  refuses to start if BROKER_KEY is unset.
- Device-code flow is cryptographically bound:
    * Plugin  POST /device-code/mint              -> gets {code, deposit_secret}
    * Plugin  POST /device-code {code, deposit_secret, token}
              - broker verifies deposit_secret (only the minter knows it)
              - broker calls BACKEND /me with the token to learn the account id,
                and binds the deposited token to that account id
    * Site    POST /device-code/exchange {code}   (Authorization: Bearer <site_token>)
              - broker calls BACKEND /me with the site token and ONLY returns the
                deposited token if the account ids match (no cross-account redeem)
- CORS is an explicit allowlist (BROKER_CORS_ORIGINS). Never '*'.
- /proxy is allowlisted to safe paths and requires BROKER_KEY. /admin, /webhooks,
  /auth, /api-keys, /device-code are blocked. BROKER_DISABLE_PROXY=1 disables it.
- Per-IP rate limiting on device-code mint/deposit/exchange.

NOTE: bind with --host 127.0.0.1 for local/single-host use. The default 0.0.0.0 is
only for the public Render deploy; the real control is BROKER_KEY + CORS + allowlist.

Run:
    BROKER_KEY=xxx python3 broker_proxy.py --host 0.0.0.0 --port 9000
"""
import argparse
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Config (fail closed)
# ---------------------------------------------------------------------------
BROKER_KEY = os.environ.get("BROKER_KEY")
if not BROKER_KEY:
    sys.stderr.write("[broker] FATAL: BROKER_KEY env not set. Refusing to start (fail-closed).\n")
    sys.exit(1)

BACKEND = os.environ.get("BACKEND", "https://api.agilebot.dev")

# CORS allowlist. Comma-separated origins. Never '*'.
_CORS_RAW = os.environ.get("BROKER_CORS_ORIGINS", "https://for-agile.onrender.com")
CORS_ORIGINS = [o.strip() for o in _CORS_RAW.split(",") if o.strip()]

DISABLE_PROXY = os.environ.get("BROKER_DISABLE_PROXY") == "1"

# Proxy path allowlist: (method, prefix). Anything else -> 403.
PROXY_ALLOW = [
    ("GET", "/me"), ("GET", "/models"), ("GET", "/plans"), ("GET", "/usage"),
    ("GET", "/conversations"), ("POST", "/conversations"),
    ("GET", "/operations"), ("POST", "/operations"),
]
PROXY_DENY_PREFIX = ("/admin", "/webhooks", "/auth", "/device-code", "/api-keys", "/billing")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
STORE = {}          # code -> {deposit_secret, token, user_id, expires, status}
TTL = int(os.environ.get("BROKER_TTL", "300"))

# Per-IP rate limiting on device-code mint/deposit/exchange.
RATE = {}
RATE_LIMIT = int(os.environ.get("BROKER_RATE_LIMIT", "30"))   # max requests
RATE_WINDOW = int(os.environ.get("BROKER_RATE_WINDOW", "60"))  # per this many seconds

# Unambiguous alphabet (no I, O, 0, 1) to avoid user transcription errors.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_RE = re.compile(r"^[A-Z0-9]{8}$")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _gen_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def _cors_headers(origin):
    """Return CORS headers only if origin is explicitly allowed. Never '*'."""
    if origin and origin in CORS_ORIGINS:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Broker-Key",
            "Vary": "Origin",
        }
    return {}


def _backend_me(token):
    """Call BACKEND /me with the token. Returns (http_status, account_id_or_None).
    Fail-closed: any error -> (502, None)."""
    if not token:
        return (401, None)
    target = BACKEND.rstrip("/") + "/me"
    req = urllib.request.Request(target, headers={
        "Authorization": "Bearer " + token,
        "User-Agent": UA,
        "Origin": CORS_ORIGINS[0] if CORS_ORIGINS else "https://for-agile.onrender.com",
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


def proxy_allowed(method, path):
    if any(path.startswith(p) for p in PROXY_DENY_PREFIX):
        return False
    norm = path[len("/proxy"):] or "/"
    for m, pref in PROXY_ALLOW:
        if m == method and norm.startswith(pref):
            return True
    return False


class BrokerHandler(BaseHTTPRequestHandler):
    # -------------------------- output --------------------------
    def _send_json(self, status, data, cors_origin=None, extra=None):
        try:
            body = json.dumps(data).encode("utf-8")
        except Exception:
            body = b'{"error": "JSON serialization failed"}'
            status = 500
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        for k, v in _cors_headers(cors_origin or self.headers.get("Origin")).items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _require_key(self):
        key = self.headers.get("X-Broker-Key", "")
        if hmac.compare_digest(key, BROKER_KEY):
            return True
        self._send_json(401, {"error": "unauthorized"}, cors_origin=self.headers.get("Origin"))
        return False

    def _rate_ok(self):
        ip = self.client_address[0]
        now = time.time()
        with lock:
            ts = RATE.get(ip, [])
            ts = [t for t in ts if now - t < RATE_WINDOW]
            if len(ts) >= RATE_LIMIT:
                RATE[ip] = ts
                self._send_json(429, {"error": "rate limited"}, cors_origin=self.headers.get("Origin"))
                return False
            ts.append(now)
            RATE[ip] = ts
        return True

    def _proxy(self):
        if DISABLE_PROXY:
            self._send_json(404, {"error": "proxy disabled"}, cors_origin=self.headers.get("Origin"))
            return
        parsed = urlparse(self.path)
        backend_path = parsed.path[len("/proxy"):] or "/"
        if not proxy_allowed(self.command, parsed.path):
            self._send_json(403, {"error": "proxy path not allowed"}, cors_origin=self.headers.get("Origin"))
            return
        target = BACKEND.rstrip("/") + backend_path
        if parsed.query:
            target += "?" + parsed.query
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
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        for k, v in _cors_headers(self.headers.get("Origin")).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp_body)

    # -------------------------- routing --------------------------
    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin and origin in CORS_ORIGINS:
            self.send_response(204)
            for k, v in _cors_headers(origin).items():
                self.send_header(k, v)
            self.end_headers()
        else:
            self.send_response(403)
            self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        origin = self.headers.get("Origin")

        if path.startswith("/proxy"):
            if not self._require_key():
                return
            self._proxy()
            return

        if path == "/health":
            self._send_json(200, {"ok": True})
            return

        if path == "/device-code/status":
            if not self._require_key():
                return
            code_list = parse_qs(parsed.query).get("code")
            if not code_list:
                self._send_json(400, {"error": "Missing code query parameter"}, cors_origin=origin)
                return
            code = code_list[0].upper()
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"found": False}, cors_origin=origin)
                    return
                entry = STORE[code]
                if now > entry["expires"]:
                    del STORE[code]
                    self._send_json(410, {"found": True, "expired": True}, cors_origin=origin)
                    return
                self._send_json(200, {"found": True, "claimed": entry["status"] == "deposited",
                                      "expired": False, "status": entry["status"]}, cors_origin=origin)
            return

        self._send_json(404, {"error": "Not found"}, cors_origin=origin)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        origin = self.headers.get("Origin")

        if path.startswith("/proxy"):
            if not self._require_key():
                return
            self._proxy()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"}, cors_origin=origin)
            return

        # ---- mint: plugin gets a code + deposit_secret ----
        if path == "/device-code/mint":
            if not self._require_key():
                return
            if not self._rate_ok():
                return
            code = _gen_code()
            dep = secrets.token_hex(16)
            with lock:
                STORE[code] = {"deposit_secret": dep, "token": None, "user_id": None,
                               "expires": time.time() + TTL, "status": "minted"}
            self._send_json(200, {"code": code, "deposit_secret": dep, "ttl": TTL}, cors_origin=origin)
            return

        # ---- deposit: plugin stores its API token, bound to account id ----
        if path == "/device-code":
            if not self._require_key():
                return
            if not self._rate_ok():
                return
            code = (data.get("code") or "").upper()
            dep = data.get("deposit_secret")
            token = data.get("token")
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"}, cors_origin=origin)
                return
            if not isinstance(dep, str) or not dep or not isinstance(token, str) or not token:
                self._send_json(400, {"error": "deposit_secret and token required"}, cors_origin=origin)
                return
            with lock:
                entry = STORE.get(code)
                if not entry or entry["status"] != "minted":
                    self._send_json(409, {"error": "code not minted or already used"}, cors_origin=origin)
                    return
                if not hmac.compare_digest(dep, entry["deposit_secret"]):
                    self._send_json(403, {"error": "bad deposit_secret"}, cors_origin=origin)
                    return
            # Verify token against backend (fail closed) and bind account id.
            st, uid = _backend_me(token)
            if st != 200 or not uid:
                self._send_json(401, {"error": "token rejected by backend"}, cors_origin=origin)
                return
            with lock:
                entry["token"] = token
                entry["user_id"] = uid
                entry["status"] = "deposited"
            print(f"[broker] deposited token for code {code} (acct {uid})", flush=True)
            self._send_json(200, {"ok": True, "ttl": TTL}, cors_origin=origin)
            return

        # ---- exchange: site redeems, only for the SAME account ----
        if path == "/device-code/exchange":
            if not self._require_key():
                return
            if not self._rate_ok():
                return
            code = (data.get("code") or "").upper()
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"}, cors_origin=origin)
                return
            site_auth = self.headers.get("Authorization", "")
            if site_auth.startswith("Bearer "):
                site_token = site_auth[7:]
            else:
                site_token = site_auth
            if not site_token:
                self._send_json(401, {"error": "site Authorization required"}, cors_origin=origin)
                return
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"error": "Code not found"}, cors_origin=origin)
                    return
                entry = STORE[code]
                if now > entry["expires"]:
                    del STORE[code]
                    self._send_json(410, {"error": "Code expired"}, cors_origin=origin)
                    return
                if entry["status"] != "deposited":
                    self._send_json(409, {"error": "code not yet deposited"}, cors_origin=origin)
                    return
                dep_uid = entry["user_id"]
                token = entry["token"]
            # Verify the site is the same account that deposited.
            st, site_uid = _backend_me(site_token)
            if st != 200 or not site_uid:
                self._send_json(401, {"error": "site token rejected by backend"}, cors_origin=origin)
                return
            if site_uid != dep_uid:
                self._send_json(403, {"error": "account mismatch"}, cors_origin=origin)
                return
            with lock:
                del STORE[code]
            self._send_json(200, {"token": token}, cors_origin=origin)
            return

        self._send_json(404, {"error": "Not found"}, cors_origin=origin)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy"):
            if not self._require_key():
                return
            self._proxy()
            return
        self._send_json(404, {"error": "Not found"}, cors_origin=self.headers.get("Origin"))


def clean_expired_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with lock:
            expired = [k for k, v in STORE.items() if now > v["expires"]]
            for k in expired:
                del STORE[k]


def main():
    global TTL
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--ttl", type=int, default=TTL)
    args = ap.parse_args()

    TTL = args.ttl

    threading.Thread(target=clean_expired_loop, daemon=True).start()

    print(f"[broker] HARDENED broker on http://{args.host}:{args.port} "
          f"(TTL={TTL}s, CORS={CORS_ORIGINS}, proxy={'disabled' if DISABLE_PROXY else 'allowlisted'}, "
          f"backend={BACKEND})", flush=True)

    server = ThreadingHTTPServer((args.host, args.port), BrokerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down broker.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import json
import re
import secrets
import hmac
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Global in-memory thread-safe store
lock = threading.Lock()
STORE = {}  # code -> { "token": token, "deposit_secret": str, "expires": float, "status": str }
TTL = 300
CODE_RE = re.compile(r"^[A-Z0-9]{8}$")

def _gen_code():
    import string
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

class BrokerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        try:
            body = json.dumps(data).encode("utf-8")
        except Exception:
            body = b'{"error": "JSON serialization failed"}'
            status = 500

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

        if path == "/health":
            self._send_json(200, {"ok": True})
            return

        if path == "/device-code/status":
            query = parse_qs(parsed.query)
            code_list = query.get("code")
            if not code_list:
                self._send_json(400, {"error": "Missing code query parameter"})
                return

            code = code_list[0]
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"found": False})
                    return

                entry = STORE[code]
                if now > entry["expires"]:
                    # expired
                    del STORE[code]
                    self._send_json(410, {"found": True, "expired": True})
                    return

                self._send_json(200, {"found": True, "claimed": False, "expired": False})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Read body
        length = int(self.headers.get("Content-Length", 0))
        body = b""
        if length > 0:
            body = self.rfile.read(length)

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path == "/device-code/mint":
            # Plugin requests a fresh code + deposit_secret (mint step).
            code = _gen_code()
            dep = secrets.token_hex(16)
            with lock:
                STORE[code] = {
                    "deposit_secret": dep,
                    "token": None,
                    "expires": time.time() + TTL,
                    "status": "minted",
                }
            self._send_json(200, {"code": code, "deposit_secret": dep, "ttl": TTL})
            return

        if path == "/device-code":
            # Deposit step: plugin submits code + deposit_secret + token.
            code = (data.get("code") or "").upper()
            dep = data.get("deposit_secret")
            token = data.get("token")

            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code. Must be 8 characters of A-Z0-9"})
                return

            if not isinstance(dep, str) or not dep or not isinstance(token, str) or not token:
                self._send_json(400, {"error": "deposit_secret and token required"})
                return

            with lock:
                entry = STORE.get(code)
                if not entry or entry.get("status") != "minted":
                    self._send_json(409, {"error": "code not minted or already used"})
                    return
                if not hmac.compare_digest(dep, entry["deposit_secret"]):
                    self._send_json(403, {"error": "bad deposit_secret"})
                    return
                # Never log token value, only code
                print(f"[broker] deposited token for code {code}", flush=True)
                entry["token"] = token
                entry["status"] = "deposited"
                entry["expires"] = time.time() + TTL

            self._send_json(200, {"ok": True, "ttl": TTL})
            return

        if path == "/device-code/exchange":
            code = data.get("code")
            if not isinstance(code, str) or not code:
                self._send_json(400, {"error": "Missing or invalid code"})
                return

            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"error": "Code not found"})
                    return

                entry = STORE[code]
                if now > entry["expires"]:
                    # expired, delete it
                    del STORE[code]
                    self._send_json(410, {"error": "Code expired"})
                    return

                token = entry["token"]
                # delete code (single-use)
                del STORE[code]

            # Return token
            self._send_json(200, {"token": token})
            return

        self._send_json(404, {"error": "Not found"})

def clean_expired_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with lock:
            expired_keys = [k for k, v in STORE.items() if now > v["expires"]]
            for k in expired_keys:
                del STORE[k]

def main():
    global TTL
    ap = argparse.ArgumentParser(description="AgileBot device-code broker")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--ttl", type=int, default=300)
    args = ap.parse_args()
    host = args.host
    port = int(os.environ.get("PORT", args.port))
    TTL = args.ttl

    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=clean_expired_loop, daemon=True)
    cleanup_thread.start()

    print(f"device-code broker on http://{host}:{port} (TTL={TTL}s, in-memory)", flush=True)
    server = ThreadingHTTPServer((host, port), BrokerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down broker.", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    main()

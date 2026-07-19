#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Global in-memory thread-safe store
lock = threading.Lock()
STORE = {}  # code -> { "token": token, "expires": float_timestamp }
TTL = 300

BACKEND = "https://api.agilebot.dev"


class BrokerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data, extra_headers=None):
        try:
            body = json.dumps(data).encode("utf-8")
        except Exception:
            body = b'{"error": "JSON serialization failed"}'
            status = 500

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self):
        # Forward to the real backend, carrying the caller's Authorization token.
        parsed = urlparse(self.path)
        # path looks like /proxy/<backend-path>
        backend_path = parsed.path[len("/proxy"):] or "/"
        target = BACKEND + backend_path
        if parsed.query:
            target += "?" + parsed.query

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        auth = self.headers.get("Authorization", "")
        origin = self.headers.get("Origin", "")
        fwd_headers = {
            "Content-Type": self.headers.get("Content-Type", "application/json"),
            "X-AgileBot-Client-Version": self.headers.get("X-AgileBot-Client-Version", "0.2.4"),
            # Cloudflare 403s the default "Python-urllib/3.x" UA — send a browser-like one.
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        }
        if auth:
            fwd_headers["Authorization"] = auth
        if origin:
            fwd_headers["Origin"] = origin

        method = self.command
        req = urllib.request.Request(target, data=body if method in ("POST", "PUT", "DELETE") else None,
                                      headers=fwd_headers, method=method)
        status = 502
        resp_body = b'{"error": "backend proxy failure"}'
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
        ct = "application/json"
        if 'resp' in dir() and hasattr(resp, "headers"):
            ct = resp.headers.get("Content-Type", "application/json")
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        self.end_headers()
        self.wfile.write(resp_body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/proxy"):
            self._proxy()
            return

        if path == "/health":
            self._send_json(200, {"ok": True})
            return

        if path == "/device-code/status":
            query = parse_qs(parsed.query)
            code_list = query.get("code")
            if not code_list:
                self._send_json(400, {"error": "Missing code query parameter"})
                return

            code = code_list[0].upper()
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"found": False})
                    return

                entry = STORE[code]
                if now > entry["expires"]:
                    del STORE[code]
                    self._send_json(410, {"found": True, "expired": True})
                    return

                self._send_json(200, {"found": True, "claimed": False, "expired": False})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/proxy"):
            self._proxy()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = b""
        if length > 0:
            body = self.rfile.read(length)

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path == "/device-code":
            code = data.get("code")
            token = data.get("token")

            if not isinstance(code, str) or not re.match(r"^[A-Z0-9]{8}$", code):
                self._send_json(400, {"error": "Invalid code. Must be 8 characters of A-Z0-9"})
                return

            if not isinstance(token, str) or not token:
                self._send_json(400, {"error": "Token cannot be empty"})
                return

            print(f"[broker] Storing code: {code}", flush=True)

            now = time.time()
            with lock:
                STORE[code] = {
                    "token": token,
                    "expires": now + TTL,
                }

            self._send_json(200, {"ok": True, "ttl": TTL})
            return

        if path == "/device-code/exchange":
            code = data.get("code")
            if not isinstance(code, str) or not code:
                self._send_json(400, {"error": "Missing or invalid code"})
                return
            code = code.upper()

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

                token = entry["token"]
                del STORE[code]

            self._send_json(200, {"token": token})
            return

        self._send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy"):
            self._proxy()
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--ttl", type=int, default=300)
    args = ap.parse_args()

    host = args.host
    port = int(os.environ.get("PORT", args.port))
    global TTL
    TTL = args.ttl

    cleanup_thread = threading.Thread(target=clean_expired_loop, daemon=True)
    cleanup_thread.start()

    print(f"device-code broker + backend proxy on http://{host}:{port} (TTL={TTL}s, in-memory, backend={BACKEND})", flush=True)

    server = ThreadingHTTPServer((host, port), BrokerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down broker.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()

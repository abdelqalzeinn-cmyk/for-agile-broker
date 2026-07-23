#!/usr/bin/env python3
"""
Simple AgileBot Device-Code Broker (FIXED)
=========================================
Fix: do_POST /proxy branch no longer re-reads self.rfile (the stream is
exhausted after the first read, so the 2nd read returned b"" and the
upstream POST got an empty body -> 422 "Field required").
"""
import json
import os
import re
import secrets
import threading
import time
import urllib.request
import urllib.error
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BACKEND = os.environ.get("BACKEND", "https://api.agilebot.dev")
TTL = int(os.environ.get("BROKER_TTL", "300"))

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_STORE = "/data/broker_store.json" if os.path.isdir("/data") else os.path.join(HERE, "broker_store.json")
STORE_FILE = os.environ.get("BROKER_STORE", DEFAULT_STORE)


def _load_store():
    try:
        with open(STORE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(store):
    tmp = STORE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(store, f)
        os.replace(tmp, STORE_FILE)
    except Exception:
        pass


lock = threading.Lock()
STORE = _load_store()
CONVERSATIONS: dict[str, dict] = {}
PENDING_MESSAGES: list[dict] = []
LAST_HEARTBEAT: dict[str, float] = {}

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_RE = re.compile(r"^[A-Z0-9]{8}$")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _gen_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def proxy_path_log(target: str) -> str:
    return target.split("://", 1)[-1]


class BrokerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", os.environ.get("AGILEBOT_WEB_ORIGIN", "https://for-agile.onrender.com"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgileBot-Client-Version")
        self.end_headers()
        self.wfile.write(body)

    def _proxy_http(self, target: str, method: str, body: bytes, fwd: dict) -> tuple:
        from urllib.parse import urlparse as _up
        import http.client as _hc
        pu = _up(target)
        host = pu.hostname or "127.0.0.1"
        port = pu.port or (443 if pu.scheme == "https" else 80)
        path_q = pu.path or "/"
        if pu.query:
            path_q += "?" + pu.query
        try:
            conn = _hc.HTTPSConnection(host, port, timeout=30) if pu.scheme == "https" \
                else _hc.HTTPConnection(host, port, timeout=30)
            conn.request(method, path_q, body=body or None, headers=fwd)
            resp = conn.getresponse()
            resp_body = resp.read() or b""
            status = resp.status
            conn.close()
        except Exception as e:
            return (502, json.dumps({"error": "backend proxy failure", "detail": str(e)}).encode("utf-8"))
        print(f"[broker] {method} {proxy_path_log(target)} -> {status}", flush=True)
        return (status, resp_body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", os.environ.get("AGILEBOT_WEB_ORIGIN", "https://for-agile.onrender.com"))
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

        if path.startswith("/api/"):
            clean = path.rstrip("/")
            if clean == "/api/pending":
                with lock:
                    items = list(PENDING_MESSAGES)
                    PENDING_MESSAGES.clear()
                self._send_json(200, {"ok": True, "messages": [{"id": i["id"], "text": i["text"]} for i in items]})
                return
            if clean == "/api/new-conversation":
                with lock:
                    items = [c for c in CONVERSATIONS.values() if not c.get("surfaced")]
                    for c in items:
                        c["surfaced"] = True
                reqs = [{"id": c["id"], "model": c.get("model")} for c in items]
                self._send_json(200, {"ok": True, "requests": reqs})
                return
            if clean == "/api/heartbeat":
                session_id = parse_qs(qs).get("session_id", [""])[0]
                now = time.time()
                last = LAST_HEARTBEAT.get(session_id, 0) if session_id else max(LAST_HEARTBEAT.values(), default=0)
                self._send_json(200, {"ok": True, "connected": bool(last and now - last <= 12), "age_seconds": (now - last) if last else None})
                return

        if path.startswith("/proxy"):
            if not self.headers.get("Authorization", "").startswith("Bearer "):
                self._send_json(401, {"error": "Authorization required"})
                return
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
            method = self.command
            # GET has no body; read once only (do not re-read rfile).
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b""
            status, resp_body = self._proxy_http(target, method, body, fwd)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Access-Control-Allow-Origin", os.environ.get("AGILEBOT_WEB_ORIGIN", "https://for-agile.onrender.com"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
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

        if path.startswith("/api/"):
            if path.rstrip("/") == "/api/heartbeat":
                # Heartbeat clients must send an object, but malformed/list JSON
                # should return a normal 400 instead of crashing the request thread.
                if not isinstance(data, dict):
                    self._send_json(400, {"error": "heartbeat body must be an object"})
                    return
                session_id = str(data.get("session_id", "")).strip()
                if session_id:
                    LAST_HEARTBEAT[session_id] = time.time()
                self._send_json(200, {"ok": True})
                return
            self._send_json(200, {"ok": True})

        if path == "/api/pending":
            text = data.get("text") or data.get("message") or ""
            if not isinstance(text, str) or not text:
                self._send_json(400, {"error": "text required"})
                return
            with lock:
                PENDING_MESSAGES.append({"id": secrets.token_hex(4), "text": text})
            self._send_json(200, {"ok": True})
            return

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
                _save_store(STORE)
            self._send_json(200, {"code": code, "deposit_secret": dep, "ttl": TTL})
            return

        if path == "/device-code":
            code = (data.get("code") or "").upper()
            dep = data.get("deposit_secret")
            token = data.get("token")
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"})
                return
            if not isinstance(token, str) or not token:
                self._send_json(400, {"error": "token required"})
                return
            uid = "local_" + uuid.uuid5(uuid.NAMESPACE_DNS, token).hex[:16]
            if not (isinstance(dep, str) and dep):
                with lock:
                    STORE[code] = {
                        "deposit_secret": secrets.token_hex(16),
                        "token": token,
                        "user_id": uid,
                        "expires": time.time() + TTL,
                        "status": "deposited",
                    }
                    _save_store(STORE)
                print(f"[broker] auto-deposited token for code {code} (local acct {uid})", flush=True)
                self._send_json(200, {"ok": True, "ttl": TTL})
                return
            with lock:
                entry = STORE.get(code)
                if not entry or entry["status"] != "minted":
                    self._send_json(409, {"error": "code not minted or already used"})
                    return
                if not secrets.compare_digest(dep, entry["deposit_secret"]):
                    self._send_json(403, {"error": "bad deposit_secret"})
                    return
                entry["token"] = token
                entry["user_id"] = uid
                entry["status"] = "deposited"
                _save_store(STORE)
            print(f"[broker] deposited token for code {code} (local acct {uid})", flush=True)
            self._send_json(200, {"ok": True, "ttl": TTL})
            return

        if path == "/device-code/status":
            qs_params = parse_qs(qs)
            code = (data.get("code") or (qs_params.get("code", [""])[0] if qs_params.get("code") else "")).upper()
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"})
                return
            now = time.time()
            with lock:
                entry = STORE.get(code)
                if not entry:
                    self._send_json(404, {"status": "not_found", "found": False})
                    return
                if now > entry["expires"]:
                    del STORE[code]
                    _save_store(STORE)
                    self._send_json(410, {"status": "expired", "found": False, "expired": True})
                    return
                if entry["status"] == "deposited":
                    self._send_json(200, {"status": "paired", "found": True, "paired": True})
                    return
                self._send_json(200, {"status": "pending", "found": True, "paired": False})
            return

        if path == "/device-code/exchange":
            code = (data.get("code") or "").upper()
            if not CODE_RE.match(code):
                self._send_json(400, {"error": "Invalid code"})
                return
            now = time.time()
            with lock:
                if code not in STORE:
                    self._send_json(404, {"error": "Code not found"})
                    return
                entry = STORE[code]
                if now > entry["expires"]:
                    del STORE[code]
                    _save_store(STORE)
                    self._send_json(410, {"error": "Code expired"})
                    return
                if entry["status"] != "deposited":
                    self._send_json(409, {"error": "code not yet deposited"})
                    return
                token = entry["token"]
                dep_uid = entry["user_id"]
            print(f"[broker] exchanged token for code {code} (acct {dep_uid})", flush=True)
            with lock:
                del STORE[code]
                _save_store(STORE)
            self._send_json(200, {"token": token})
            return

        if path.startswith("/proxy"):
            if not self.headers.get("Authorization", "").startswith("Bearer "):
                self._send_json(401, {"error": "Authorization required"})
                return
            proxy_path = path[len("/proxy"):] or "/"
            target = BACKEND.rstrip("/") + proxy_path
            if qs:
                target += "?" + qs
            # body was ALREADY read once at the top of do_POST into `body`.
            # Do NOT call self.rfile.read() again here - the stream is exhausted
            # and a second read returns b"" -> empty body -> upstream 422.
            auth = self.headers.get("Authorization", "")
            fwd = {
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "X-AgileBot-Client-Version": self.headers.get("X-AgileBot-Client-Version", "0.2.4"),
                "User-Agent": UA,
            }
            if auth:
                fwd["Authorization"] = auth
            method = self.command
            status, resp_body = self._proxy_http(target, method, body, fwd)
            if status == 200 and proxy_path == "/conversations" and method == "POST":
                try:
                    j = json.loads(resp_body.decode("utf-8"))
                    cid = j.get("id") or j.get("conversation_id")
                    if cid:
                        with lock:
                            CONVERSATIONS[cid] = {
                                "id": cid,
                                "model": (data.get("model") if isinstance(data, dict) else None),
                                "surfaced": False,
                                "created_at": time.time(),
                            }
                except Exception:
                    pass
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Access-Control-Allow-Origin", os.environ.get("AGILEBOT_WEB_ORIGIN", "https://for-agile.onrender.com"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
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
            if expired:
                for k in expired:
                    del STORE[k]
                _save_store(STORE)


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

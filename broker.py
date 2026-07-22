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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BACKEND = os.environ.get("BACKEND", "https://api.agilebot.dev")
TTL = int(os.environ.get("BROKER_TTL", "300"))

# Durable store: survives cold starts / redeploys. Point BROKER_STORE at a
# persistent disk (e.g. Render's /data) so multiple instances share it too.
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
STORE = _load_store()  # code -> {deposit_secret, token, user_id, expires, status}
# Conversations/messages that flow through the broker pairing tunnel. The site
# polls /api/new-conversation + /api/pending expecting the broker to surface
# what the plugin created; previously these returned null/empty forever, so the
# site looped. We record proxied conversations + messages here and expose them.
CONVERSATIONS: dict[str, dict] = {}
PENDING_MESSAGES: list[dict] = []  # user-typed messages the site wants the plugin to run

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
        # real backend (api.agilebot.dev has NO /api prefix). These are the
        # pairing-tunnel state endpoints the site polls to surface conversations
        # and user-typed messages that flow through this broker.
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
                # also surface any conversation created via /proxy/conversations
                self._send_json(200, {"ok": True, "requests": reqs})
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

        # /api/* state endpoints the site POSTs to (heartbeat, etc.)
        if path.startswith("/api/"):
            if path.rstrip("/") == "/api/heartbeat":
                self._send_json(200, {"ok": True})
                return
            self._send_json(200, {"ok": True})

        # Site pushes a user-typed message into the pairing tunnel; the plugin
        # polls GET /api/pending to pick it up and run it.
        if path == "/api/pending":
            text = data.get("text") or data.get("message") or ""
            if not isinstance(text, str) or not text:
                self._send_json(400, {"error": "text required"})
                return
            with lock:
                PENDING_MESSAGES.append({"id": secrets.token_hex(4), "text": text})
            self._send_json(200, {"ok": True})
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
                _save_store(STORE)
            self._send_json(200, {"code": code, "deposit_secret": dep, "ttl": TTL})
            return

        # deposit: plugin stores its API token, bound to account id.
        # Two protocol variants are accepted:
        #   (A) hardened: {code, deposit_secret, token} (deposit_secret from /device-code/mint)
        #   (B) simplified mod: {code, token} only -> auto-mint the code here
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
            # Local broker: trust the token locally. We deliberately do NOT call
            # the real backend's /me here — the plugin/mod sends a LOCAL token
            # (from plugin:GetSetting), not valid prod creds, so a prod /me check
            # would always 401 and break pairing ("backend rejected token?").
            # Instead we derive a stable virtual user_id from the token so the
            # rest of the flow (exchange -> token bound to code) works offline.
            uid = "local_" + uuid.uuid5(uuid.NAMESPACE_DNS, token).hex[:16]
            # Variant B: no deposit_secret -> auto-mint (simplified mod flow)
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
            # Variant A: hardened mint+deposit
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

        # status: simplified mod poll (returns the live state of a code)
        if path == "/device-code/status":
            # The mod sends the code as a query param (?code=XYZ); accept body or query.
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

        # exchange: site redeems by code alone (the plugin already deposited
        # its token bound to this code). No site Authorization required.
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

        # proxy: forward to backend
        if path.startswith("/proxy"):
            import sys as _sys
            print(f"[dbg] POST proxy start target={BACKEND.rstrip('/') + (path[len('/proxy'):] or '/')}", flush=True)
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
            # Record conversations/messages that flow through the pairing tunnel
            # so the site's /api/new-conversation + /api/pending can surface them
            # (otherwise the site polls forever and never renders).
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

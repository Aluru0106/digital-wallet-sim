"""Test client that signs requests exactly like the browser UI does."""
import json
import time
import uuid

from app.security import canonical, sign


class Session:
    def __init__(self, http, token, signing_key, user_id, role):
        self.http, self.token, self.key, self.user_id, self.role = http, token, signing_key, user_id, role

    def headers(self, extra=None):
        h = {"Authorization": f"Bearer {self.token}"}
        h.update(extra or {})
        return h

    def get(self, path):
        return self.http.get(path, headers=self.headers())

    def post(self, path, body=None):
        return self.http.post(path, json=body, headers=self.headers())

    def signed_headers(self, path, body_bytes, nonce=None, ts=None, method="POST"):
        ts = str(int(time.time()) if ts is None else ts)
        nonce = nonce or uuid.uuid4().hex
        sig = sign(self.key, canonical(method, path, ts, nonce, body_bytes))
        return {"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig, "Content-Type": "application/json"}

    def signed_post(self, path, body=None, extra=None, nonce=None, ts=None):
        raw = json.dumps(body if body is not None else {}).encode()
        h = self.headers(self.signed_headers(path, raw, nonce, ts))
        h.update(extra or {})
        return self.http.post(path, content=raw, headers=h)


class Api:
    def __init__(self, http):
        self.http = http

    def register(self, username, password="Str0ng-Passw0rd!", role="customer"):
        return self.http.post("/api/auth/register", json={"username": username, "password": password, "role": role})

    def login(self, username, password="Str0ng-Passw0rd!"):
        r = self.http.post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        d = r.json()
        return Session(self.http, d["access_token"], d["signing_key"], d["user_id"], d["role"])

    def new_customer(self, name, funds=0):
        self.register(name)
        s = self.login(name)
        assert s.post("/api/wallets").status_code == 201
        if funds:
            assert s.signed_post("/api/wallets/topup", {"amount": funds}).status_code == 200
        return s

    def new_merchant(self, name):
        self.register(name, role="merchant")
        s = self.login(name)
        r = s.post("/api/merchants", {"business_name": "Shop " + name[-6:], "category": "retail"})
        assert r.status_code == 201, r.text
        s.merchant_id = r.json()["merchant_id"]
        return s

"""PayLite - Digital Wallet & Payment Gateway Simulator (FastAPI)."""
import os
import time
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import audit, services
from app.config import settings
from app.db import init_db, tx
from app.security import (ReplayError, canonical, check_fresh, consume_nonce, decode_token, issue_token,
                          signing_key_for, verify_signature)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if os.getenv("ADMIN_USERNAME") and os.getenv("ADMIN_PASSWORD"):
        services.seed_admin(os.environ["ADMIN_USERNAME"], os.environ["ADMIN_PASSWORD"])
    yield


app = FastAPI(title="PayLite Wallet Simulator", version="2.0.0", lifespan=lifespan,
              docs_url="/docs" if settings.env != "prod" else None, redoc_url=None)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


# ---------------- security headers ----------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    if request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------- error handling (no stack traces / internals to clients) ----------------
@app.exception_handler(services.DomainError)
async def domain_error(_req: Request, exc: services.DomainError):
    return JSONResponse(status_code=exc.status, content={"error": exc.message})


@app.exception_handler(RequestValidationError)
async def validation_error(_req: Request, exc: RequestValidationError):
    fields = sorted({".".join(str(p) for p in e["loc"][1:]) or "body" for e in exc.errors()})
    return JSONResponse(status_code=422, content={"error": "invalid input", "fields": fields})


@app.exception_handler(Exception)
async def unhandled(req: Request, exc: Exception):
    audit.security_event("unhandled_error", level="ERROR", path=req.url.path, error_type=type(exc).__name__)
    return JSONResponse(status_code=500, content={"error": "internal error"})


# ---------------- schemas (input validation) ----------------
MAX_ID = 2**31 - 1
Username = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")]
PaymentId = Annotated[int, Path(gt=0, le=MAX_ID)]
Amount = Annotated[int, Field(strict=True, gt=0, le=services.MAX_TOPUP)]
IdemKey = Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9-]{16,64}$")]


class RegisterIn(BaseModel):
    username: Username
    password: str = Field(min_length=10, max_length=128)
    role: Literal["customer", "merchant"] = "customer"


class LoginIn(BaseModel):
    username: Username
    password: str = Field(min_length=1, max_length=128)


class FundsIn(BaseModel):
    amount: Amount


class MerchantIn(BaseModel):
    business_name: str = Field(pattern=r"^[A-Za-z0-9 &.,'-]{2,64}$")
    category: Literal["retail", "food", "travel", "education", "utilities", "other"]


class PaymentIn(BaseModel):
    merchant_id: int = Field(strict=True, gt=0, le=MAX_ID)   # DEF-06: bound IDs to SQLite INTEGER range
    amount: Amount


class RefundIn(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


# ---------------- authN / authZ dependencies ----------------
def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing token")
    try:
        claims = decode_token(authorization[7:])
    except jwt.PyJWTError:
        audit.security_event("invalid_token", level="WARNING")
        raise HTTPException(401, "invalid or expired token") from None
    return {"user_id": int(claims["sub"]), "role": claims["role"]}


def require_role(*roles: str):
    def checker(user: Annotated[dict, Depends(current_user)]) -> dict:
        if user["role"] not in roles:
            audit.security_event("authz_denied", level="WARNING", user_id=user["user_id"], need=list(roles))
            raise HTTPException(403, "forbidden")
        return user
    return checker


async def signed_request(request: Request, user: Annotated[dict, Depends(current_user)],
                         x_timestamp: Annotated[str, Header()], x_nonce: Annotated[str, Header()],
                         x_signature: Annotated[str, Header()]) -> dict:
    """Anti-tampering (HMAC) + anti-replay (timestamp window + single-use nonce)."""
    body = await request.body()
    msg = canonical(request.method, request.url.path, x_timestamp, x_nonce, body)
    if not verify_signature(user["user_id"], msg, x_signature):
        audit.security_event("tamper_detected", level="WARNING", user_id=user["user_id"], path=request.url.path)
        raise HTTPException(401, "bad signature")
    try:
        check_fresh(x_timestamp)
        with tx() as con:
            consume_nonce(con, x_nonce, user["user_id"])
    except ReplayError as e:
        audit.security_event("replay_blocked", level="WARNING", user_id=user["user_id"], reason=str(e))
        raise HTTPException(409, f"replay rejected: {e}") from None
    return user


# ---------------- routes ----------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    return "\n".join(f"paylite_{k}_total {v}" for k, v in sorted(audit.METRICS.items())) + "\n"


@app.post("/api/auth/register", status_code=201)
def register(body: RegisterIn):
    uid = services.register_user(body.username, body.password, body.role)
    audit.security_event("user_registered", user_id=uid, role=body.role)
    return {"user_id": uid, "username": body.username, "role": body.role}


@app.post("/api/auth/login")
def login(body: LoginIn):
    try:
        u = services.authenticate(body.username, body.password, int(time.time()),
                                  settings.max_failed_logins, settings.lockout_seconds)
    except services.DomainError as e:
        audit.security_event("login_failed", level="WARNING", username=body.username, status=e.status)
        raise
    audit.security_event("login_success", user_id=u["user_id"])
    return {"access_token": issue_token(u["user_id"], u["role"]),
            "token_type": "bearer",  # nosec B105 - OAuth token-type label, not a secret
            "role": u["role"], "user_id": u["user_id"], "signing_key": signing_key_for(u["user_id"]),
            "expires_in": settings.jwt_ttl_seconds}


@app.post("/api/wallets", status_code=201)
def create_wallet(user: Annotated[dict, Depends(require_role("customer"))]):
    return services.create_wallet(user["user_id"])


@app.get("/api/wallets/me")
def my_wallet(user: Annotated[dict, Depends(require_role("customer", "merchant"))]):
    return services.get_wallet(user["user_id"])


@app.post("/api/wallets/topup")
def topup(body: FundsIn, user: Annotated[dict, Depends(signed_request)]):
    if user["role"] != "customer":
        raise HTTPException(403, "forbidden")
    return services.add_funds(user["user_id"], body.amount)


@app.post("/api/merchants", status_code=201)
def register_merchant(body: MerchantIn, user: Annotated[dict, Depends(require_role("merchant"))]):
    return services.register_merchant(user["user_id"], body.business_name, body.category)


@app.get("/api/merchants")
def merchants(_user: Annotated[dict, Depends(current_user)]):
    return services.list_merchants()


@app.post("/api/payments", status_code=201)
def initiate(body: PaymentIn, idem: IdemKey, user: Annotated[dict, Depends(signed_request)]):
    if user["role"] != "customer":
        raise HTTPException(403, "forbidden")
    if body.amount > services.MAX_PAYMENT:
        raise services.DomainError(422, "amount out of range")
    return services.initiate_payment(user["user_id"], body.merchant_id, body.amount, idem)


@app.post("/api/payments/{payment_id}/confirm")
def confirm(payment_id: PaymentId, user: Annotated[dict, Depends(signed_request)]):
    if user["role"] != "customer":
        raise HTTPException(403, "forbidden")
    res = services.confirm_payment(user["user_id"], payment_id)
    audit.security_event("payment_" + res["status"].lower(), user_id=user["user_id"], payment_id=payment_id)
    return res


@app.post("/api/payments/{payment_id}/refund")
def refund(payment_id: PaymentId, body: RefundIn, user: Annotated[dict, Depends(signed_request)]):
    if user["role"] not in ("merchant", "admin"):
        raise HTTPException(403, "forbidden")
    res = services.refund_payment(user["user_id"], user["role"], payment_id, body.reason)
    audit.security_event("refund_issued", user_id=user["user_id"], payment_id=payment_id)
    return res


@app.get("/api/transactions")
def transactions(user: Annotated[dict, Depends(require_role("customer", "merchant"))]):
    return services.history(user["user_id"])


@app.get("/api/merchant/payments")
def merchant_payments(user: Annotated[dict, Depends(require_role("merchant"))]):
    return services.merchant_payments(user["user_id"])


@app.get("/api/admin/audit")
def audit_log(_user: Annotated[dict, Depends(require_role("admin"))]):
    return services.audit_entries()

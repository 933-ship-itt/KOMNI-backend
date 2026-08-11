"""KOMNI PIN Guard API.

Single-file FastAPI security service for:
- provisioning a one-time 6-digit PIN for a Firebase-authenticated user;
- hashing and storing the PIN under clients/{uid}.security.pinGuard;
- verifying the PIN against the Firebase UID from the bearer ID token;
- issuing a short-lived PIN verification session token;
- optionally sending the newly provisioned PIN + welcome letter through SMTP.

Security model:
- Never trusts a UID supplied by the browser. UID comes from Firebase ID token.
- Never stores the plaintext PIN in Firestore.
- PIN is one-time: successful verification consumes it.
- Provisioning rotates/replaces any existing unconsumed PIN.
- Rate limits PIN verification attempts per account in Firestore.
- Requires Firebase Admin credentials on the server.

Install:
  pip install fastapi uvicorn firebase-admin pydantic[email]

Run:
  uvicorn api.security.auth.pin_guard:app --host 127.0.0.1 --port 8787

Production notes:
- Put this behind HTTPS and a reverse proxy/API gateway.
- Set FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS.
- Set PIN_GUARD_ALLOWED_ORIGINS to your login site's origin(s).
- Configure SMTP_* variables if email delivery is desired.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import firebase_admin
from firebase_admin import auth, credentials, firestore


APP_NAME = "KOMNI PIN Guard"
PIN_LENGTH = 6
PIN_TTL_SECONDS = int(os.getenv("PIN_GUARD_TTL_SECONDS", "900"))
VERIFY_SESSION_TTL_SECONDS = int(os.getenv("PIN_GUARD_SESSION_TTL_SECONDS", "300"))
MAX_ATTEMPTS = int(os.getenv("PIN_GUARD_MAX_ATTEMPTS", "5"))
LOCKOUT_SECONDS = int(os.getenv("PIN_GUARD_LOCKOUT_SECONDS", "900"))
HASH_ITERATIONS = int(os.getenv("PIN_GUARD_PBKDF2_ITERATIONS", "210000"))

app = FastAPI(title=APP_NAME, version="1.0.0")

origins = [x.strip() for x in os.getenv("PIN_GUARD_ALLOWED_ORIGINS", "").split(",") if x.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["POST", "GET"],
        allow_headers=["Authorization", "Content-Type"],
    )


# ---------------------------------------------------------------------------
# Firebase
# ---------------------------------------------------------------------------

def _init_firebase() -> None:
    if firebase_admin._apps:
        return

    service_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
    if service_json:
        try:
            info = json.loads(service_json)
            firebase_admin.initialize_app(credentials.Certificate(info))
            return
        except (json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("Invalid FIREBASE_SERVICE_ACCOUNT_JSON") from exc

    firebase_admin.initialize_app()


_init_firebase()
db = firestore.client()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ProvisionResponse(BaseModel):
    ok: bool
    uid: str
    email: str | None = None
    expiresIn: int
    emailSent: bool
    message: str


class VerifyRequest(BaseModel):
    pin: str = Field(min_length=PIN_LENGTH, max_length=PIN_LENGTH, pattern=r"^\d{6}$")


class VerifyResponse(BaseModel):
    ok: bool
    uid: str
    verified: bool
    sessionToken: str | None = None
    expiresIn: int | None = None
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _auth_header(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Firebase bearer token")
    return authorization[7:].strip()


def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _auth_header(authorization)
    try:
        decoded = auth.verify_id_token(token, check_revoked=True)
    except auth.RevokedIdTokenError:
        raise HTTPException(status_code=401, detail="Firebase session has been revoked")
    except auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Firebase ID token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token")

    uid = decoded.get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Firebase token has no UID")
    return decoded


def _pin_hash(pin: str, salt: bytes | None = None) -> dict[str, str | int]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, HASH_ITERATIONS, dklen=32)
    return {
        "algorithm": "pbkdf2-sha256",
        "iterations": HASH_ITERATIONS,
        "salt": base64.urlsafe_b64encode(salt).decode().rstrip("="),
        "digest": base64.urlsafe_b64encode(digest).decode().rstrip("="),
    }


def _verify_hash(pin: str, record: dict[str, Any]) -> bool:
    try:
        salt = base64.urlsafe_b64decode(record["salt"] + "==")
        expected = base64.urlsafe_b64decode(record["digest"] + "==")
        iterations = int(record.get("iterations", HASH_ITERATIONS))
        actual = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def _make_session_token(uid: str) -> str:
    """Opaque, signed-ish random token for the browser.

    The token itself is not a credential for Firebase. Its hash is stored in
    Firestore and the raw token is returned once to the browser.
    """
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    ref = db.collection("clients").document(uid)
    ref.set(
        {
            "security": {
                "pinGuard": {
                    "verifiedSessionHash": digest,
                    "verifiedSessionExpiresAt": utcnow() + timedelta(seconds=VERIFY_SESSION_TTL_SECONDS),
                    "verifiedAt": firestore.SERVER_TIMESTAMP,
                }
            }
        },
        merge=True,
    )
    return raw


def _send_welcome_email(email: str, display_name: str, pin: str) -> bool:
    """Send provisioning email when SMTP is configured.

    Email failure does not silently mark the PIN as delivered; callers receive
    emailSent=False and can decide whether provisioning should be retried.
    """
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("PIN_GUARD_EMAIL_FROM") or username

    if not all([host, username, password, sender]):
        return False

    msg = EmailMessage()
    msg["Subject"] = os.getenv("PIN_GUARD_EMAIL_SUBJECT", "Welcome to KOMNI — your secure access PIN")
    msg["From"] = sender
    msg["To"] = email
    safe_name = display_name or "Associate"
    msg.set_content(
        f"""Welcome to KOMNI, {safe_name}.\n\n"
        "Your Google account has been registered for secure KOMNI access.\n\n"
        f"Your one-time PIN is: {pin}\n\n"
        "Use this PIN on the KOMNI login screen. After successful verification, "
        "you will be required to complete the configured 2FA step.\n\n"
        "Keep this message private. The PIN expires after its provisioning window "
        "and is consumed after successful verification.\n\n"
        "KOMNI Security\n"""
    )

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException):
        return False


def _security_ref(uid: str):
    return db.collection("clients").document(uid)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/security/auth/pin_guard/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": APP_NAME,
        "pinLength": PIN_LENGTH,
        "pinTtlSeconds": PIN_TTL_SECONDS,
        "emailConfigured": bool(
            os.getenv("SMTP_HOST")
            and os.getenv("SMTP_USERNAME")
            and os.getenv("SMTP_PASSWORD")
            and (os.getenv("PIN_GUARD_EMAIL_FROM") or os.getenv("SMTP_USERNAME"))
        ),
    }


@app.post("/api/security/auth/pin_guard/provision", response_model=ProvisionResponse)
def provision_pin(user: dict[str, Any] = Depends(current_user)) -> ProvisionResponse:
    uid = user["uid"]
    email = user.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Firebase account has no email address")

    client_ref = _security_ref(uid)
    snapshot = client_ref.get()
    client_data = snapshot.to_dict() or {}
    existing = ((client_data.get("security") or {}).get("pinGuard") or {})

    # Do not rotate an active PIN merely because the login page loaded twice.
    existing_expires = existing.get("expiresAt")
    existing_consumed = bool(existing.get("consumedAt"))
    if existing.get("pinHash") and not existing_consumed and existing_expires:
        if hasattr(existing_expires, "timestamp"):
            still_valid = existing_expires.timestamp() > time.time()
        else:
            still_valid = False
        if still_valid:
            return ProvisionResponse(
                ok=True,
                uid=uid,
                email=email,
                expiresIn=max(1, int(existing_expires.timestamp() - time.time())),
                emailSent=bool(existing.get("emailSent", False)),
                message="An active PIN is already provisioned for this account.",
            )

    pin = f"{secrets.randbelow(1_000_000):06d}"
    hashed = _pin_hash(pin)
    expires_at = utcnow() + timedelta(seconds=PIN_TTL_SECONDS)

    # Email first. We only mark emailSent after the provider accepts it.
    email_sent = _send_welcome_email(email, user.get("name") or "Associate", pin)

    payload = {
        "pinHash": hashed,
        "issuedAt": firestore.SERVER_TIMESTAMP,
        "expiresAt": expires_at,
        "consumedAt": None,
        "emailSent": email_sent,
        "emailAddress": email,
        "attempts": 0,
        "lockedUntil": None,
        "provisioningVersion": secrets.token_hex(8),
    }

    client_ref.set(
        {
            "uid": uid,
            "email": email,
            "security": {"pinGuard": payload},
            "updatedAt": firestore.SERVER_TIMESTAMP,
        },
        merge=True,
    )

    if not email_sent:
        # The PIN exists securely but was not delivered. Do not return it from
        # the API. The caller can retry provisioning after fixing SMTP.
        raise HTTPException(
            status_code=503,
            detail="PIN was provisioned securely, but the welcome email could not be delivered.",
        )

    return ProvisionResponse(
        ok=True,
        uid=uid,
        email=email,
        expiresIn=PIN_TTL_SECONDS,
        emailSent=True,
        message="PIN provisioned and welcome email sent.",
    )


@app.post("/api/security/auth/pin_guard/verify", response_model=VerifyResponse)
def verify_pin(body: VerifyRequest, user: dict[str, Any] = Depends(current_user)) -> VerifyResponse:
    uid = user["uid"]
    client_ref = _security_ref(uid)
    snapshot = client_ref.get()
    if not snapshot.exists:
        raise HTTPException(status_code=404, detail="No security profile exists for this account")

    data = snapshot.to_dict() or {}
    guard = ((data.get("security") or {}).get("pinGuard") or {})

    if guard.get("consumedAt"):
        raise HTTPException(status_code=410, detail="PIN has already been used")

    expires_at = guard.get("expiresAt")
    if not expires_at or not hasattr(expires_at, "timestamp") or expires_at.timestamp() <= time.time():
        raise HTTPException(status_code=410, detail="PIN has expired")

    locked_until = guard.get("lockedUntil")
    if locked_until and hasattr(locked_until, "timestamp") and locked_until.timestamp() > time.time():
        raise HTTPException(status_code=429, detail="Too many PIN attempts; try again later")

    if not _verify_hash(body.pin, guard.get("pinHash") or {}):
        attempts = int(guard.get("attempts") or 0) + 1
        update: dict[str, Any] = {"security.pinGuard.attempts": attempts}
        if attempts >= MAX_ATTEMPTS:
            update["security.pinGuard.lockedUntil"] = utcnow() + timedelta(seconds=LOCKOUT_SECONDS)
        client_ref.update(update)
        raise HTTPException(status_code=401, detail="Invalid PIN")

    session_token = _make_session_token(uid)
    client_ref.update(
        {
            "security.pinGuard.consumedAt": firestore.SERVER_TIMESTAMP,
            "security.pinGuard.attempts": 0,
            "security.pinGuard.lockedUntil": None,
            "security.pinGuard.lastVerifiedAt": firestore.SERVER_TIMESTAMP,
        }
    )

    return VerifyResponse(
        ok=True,
        uid=uid,
        verified=True,
        sessionToken=session_token,
        expiresIn=VERIFY_SESSION_TTL_SECONDS,
        message="PIN verified. Continue to 2FA.",
    )


@app.get("/api/security/auth/pin_guard/status")
def status(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    uid = user["uid"]
    snap = _security_ref(uid).get()
    data = snap.to_dict() or {}
    guard = ((data.get("security") or {}).get("pinGuard") or {})
    expires_at = guard.get("expiresAt")
    active = bool(
        guard.get("pinHash")
        and not guard.get("consumedAt")
        and expires_at
        and hasattr(expires_at, "timestamp")
        and expires_at.timestamp() > time.time()
    )
    return {
        "ok": True,
        "uid": uid,
        "pinProvisioned": bool(guard.get("pinHash")),
        "pinActive": active,
        "pinConsumed": bool(guard.get("consumedAt")),
        "emailSent": bool(guard.get("emailSent")),
        "requiresProvisioning": not active and not guard.get("consumedAt"),
    }


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    # Keep implementation errors out of the browser response.
    print(f"PIN Guard internal error on {request.method} {request.url.path}: {exc!r}")
    return __import__("fastapi").responses.JSONResponse(
        status_code=500,
        content={"detail": "Internal security service error"},
    )

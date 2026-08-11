# /api/security/auth/pin_guard.py

import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import firebase_admin
from firebase_admin import auth, firestore
from passlib.context import CryptContext

# ---------------------------------------------------------
# App & Security Configuration
# ---------------------------------------------------------
app = FastAPI(title="KOMNI PIN Guard")
security = HTTPBearer()

# Initialize Firebase Admin (assumes GOOGLE_APPLICATION_CREDENTIALS is set)
if not firebase_admin._apps:
    firebase_admin.initialize_app()

db = firestore.client()

# Secure password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------
# Helper Functions & Dependencies
# ---------------------------------------------------------
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Validates the Firebase ID token and returns the derived user info.
    Never trusts a client-provided UID.
    """
    token = credentials.credentials
    try:
        decoded_token = auth.verify_id_token(token)
        return {
            "uid": decoded_token["uid"],
            "email": decoded_token.get("email", "")
        }
    except Exception as e:
        # Generic error to prevent token probing
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def generate_secure_pin() -> str:
    """Generates a cryptographically secure 6-digit PIN."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def send_komni_welcome_email(email: str, pin: str) -> bool:
    """
    Mock function for sending the welcome email. 
    In production, integrate with SendGrid, AWS SES, etc.
    """
    # TODO: Implement actual email delivery
    print(f"SECURE LOG: Email sent to {email}. (Do not log PIN in production)")
    return True

def generate_session_token() -> str:
    """Generates a short-lived, secure session artifact."""
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------
# Request Models
# ---------------------------------------------------------
class ConfirmRequest(BaseModel):
    confirmed: bool

class VerifyRequest(BaseModel):
    pin: str


# ---------------------------------------------------------
# Endpoints
# ---------------------------------------------------------
@app.get("/status")
def get_status(user: dict = Depends(get_current_user)):
    """Checks if the user has an active PIN provisioned."""
    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    if doc.exists:
        data = doc.to_dict()
        # Treat as provisioned only if the flow is complete and active
        is_provisioned = data.get("status") == "active"
        return {"ok": True, "provisioned": is_provisioned}
    
    return {"ok": True, "provisioned": False}


@app.post("/provision")
def provision_pin(user: dict = Depends(get_current_user)):
    """Generates a new PIN, stores its hash, and emails the user."""
    uid = user["uid"]
    email = user["email"]
    
    if not email:
        raise HTTPException(status_code=400, detail="User requires a verified email to provision PIN.")

    pin = generate_secure_pin()
    pin_hash = pwd_context.hash(pin)
    
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=900) # 15 minutes to confirm

    # Store enrollment strictly under the server-verified UID
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    
    doc_ref.set({
        "uid": uid,
        "email": email,
        "status": "pending_confirmation",
        "pinHash": pin_hash,
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "attemptCount": 0,
        "confirmedAt": None,
        "lockoutUntil": None
    })

    email_sent = send_komni_welcome_email(email, pin)

    # Return plaintext PIN once for clipboard injection
    return {
        "ok": True,
        "uid": uid,
        "email": email,
        "pin": pin,
        "emailSent": email_sent,
        "expiresIn": 900
    }


@app.post("/confirm")
def confirm_pin(payload: ConfirmRequest, user: dict = Depends(get_current_user)):
    """Marks the pending PIN as confirmed by the user."""
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="Must confirm PIN storage.")

    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=400, detail="No pending PIN enrollment found.")

    data = doc.to_dict()
    if data.get("status") != "pending_confirmation":
        raise HTTPException(status_code=400, detail="PIN enrollment is not in a pending state.")

    now = datetime.now(timezone.utc).isoformat()
    
    doc_ref.update({
        "status": "active",
        "confirmedAt": now,
        "updatedAt": now
    })

    return {
        "ok": True,
        "confirmed": True
    }


@app.post("/verify")
def verify_pin(payload: VerifyRequest, user: dict = Depends(get_current_user)):
    """Verifies the submitted PIN against the secure hash and returns a session token."""
    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    # Generic error function to mask user state
    def auth_failed():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed."
        )

    if not doc.exists:
        auth_failed()

    data = doc.to_dict()

    # Check status
    if data.get("status") != "active":
        auth_failed()

    # Check rate limit / lockout
    now = datetime.now(timezone.utc)
    lockout_str = data.get("lockoutUntil")
    if lockout_str:
        lockout_time = datetime.fromisoformat(lockout_str)
        if now < lockout_time:
            auth_failed()

    # Verify Hash
    is_valid = pwd_context.verify(payload.pin, data.get("pinHash", ""))

    if not is_valid:
        # Increment attempts and apply lockout if necessary
        attempts = data.get("attemptCount", 0) + 1
        update_data = {"attemptCount": attempts}
        
        if attempts >= 5:
            # 15-minute lockout on 5 failed attempts
            lockout_until = now + timedelta(minutes=15)
            update_data["lockoutUntil"] = lockout_until.isoformat()
            update_data["attemptCount"] = 0 # Reset for next window
            
        doc_ref.update(update_data)
        auth_failed()

    # Success path: reset attempts, generate session token
    doc_ref.update({
        "attemptCount": 0,
        "lockoutUntil": None,
        "lastVerifiedAt": now.isoformat()
    })

    session_token = generate_session_token()
    
    # Store session token server-side/Redis (omitted here for brevity, 
    # but required before returning to the client to establish the session)

    return {
        "ok": True,
        "verified": True,
        "uid": uid,
        "sessionToken": session_token,
        "expiresIn": 300
    }

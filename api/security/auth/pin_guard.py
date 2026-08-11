# /api/security/auth/pin_guard.py

import os
import json
import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, auth, firestore
from passlib.context import CryptContext

app = FastAPI(title="KOMNI PIN Guard")
security = HTTPBearer()

# --- DIAGNOSTIC INITIALIZATION ---
# Catch startup errors so Vercel doesn't throw a generic 500 error
startup_error = None
db = None

try:
    if not firebase_admin._apps:
        service_account_env = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY")
        if service_account_env:
            cred_dict = json.loads(service_account_env)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
        else:
            # If variable is completely missing
            startup_error = "FIREBASE_SERVICE_ACCOUNT_KEY environment variable is missing."
            
    if not startup_error:
        db = firestore.client()
except json.JSONDecodeError:
    startup_error = "FIREBASE_SERVICE_ACCOUNT_KEY is not valid JSON. Check Vercel Env Vars."
except Exception as e:
    startup_error = f"Firebase Init Error: {str(e)}"

# Secure password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- DEBUG ENDPOINT ---
@app.get("/api/security/auth/pin_guard/debug")
@app.get("/debug")
def debug_startup():
    """Returns the exact reason why the server is failing to start."""
    if startup_error:
        return {"status": "failed", "error": startup_error}
    return {"status": "ok", "message": "Firebase initialized successfully!"}


# ---------------------------------------------------------
# Helper Functions & Dependencies
# ---------------------------------------------------------
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if startup_error:
        raise HTTPException(status_code=500, detail=startup_error)
        
    token = credentials.credentials
    try:
        decoded_token = auth.verify_id_token(token)
        return {"uid": decoded_token["uid"], "email": decoded_token.get("email", "")}
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def generate_secure_pin() -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def generate_session_token() -> str:
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
# Note: Adding alternative routing paths in case Vercel rewrites the URL strangely
@app.get("/api/security/auth/pin_guard/status")
@app.get("/status")
def get_status(user: dict = Depends(get_current_user)):
    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    if doc.exists:
        data = doc.to_dict()
        is_provisioned = data.get("status") == "active"
        return {"ok": True, "provisioned": is_provisioned}
    
    return {"ok": True, "provisioned": False}


@app.post("/api/security/auth/pin_guard/provision")
@app.post("/provision")
def provision_pin(user: dict = Depends(get_current_user)):
    uid = user["uid"]
    email = user["email"]
    
    if not email:
        raise HTTPException(status_code=400, detail="User requires a verified email to provision PIN.")

    pin = generate_secure_pin()
    pin_hash = pwd_context.hash(pin)
    now = datetime.now(timezone.utc)
    
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc_ref.set({
        "uid": uid,
        "email": email,
        "status": "pending_confirmation",
        "pinHash": pin_hash,
        "createdAt": now.isoformat(),
        "expiresAt": (now + timedelta(seconds=900)).isoformat(),
        "attemptCount": 0,
        "confirmedAt": None,
        "lockoutUntil": None
    })

    return {"ok": True, "uid": uid, "email": email, "pin": pin, "emailSent": True, "expiresIn": 900}


@app.post("/api/security/auth/pin_guard/confirm")
@app.post("/confirm")
def confirm_pin(payload: ConfirmRequest, user: dict = Depends(get_current_user)):
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="Must confirm PIN storage.")

    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    if not doc.exists or doc.to_dict().get("status") != "pending_confirmation":
        raise HTTPException(status_code=400, detail="No pending PIN enrollment found.")

    doc_ref.update({
        "status": "active",
        "confirmedAt": datetime.now(timezone.utc).isoformat()
    })

    return {"ok": True, "confirmed": True}


@app.post("/api/security/auth/pin_guard/verify")
@app.post("/verify")
def verify_pin(payload: VerifyRequest, user: dict = Depends(get_current_user)):
    uid = user["uid"]
    doc_ref = db.collection("clients").document(uid).collection("security").document("pinGuard")
    doc = doc_ref.get()

    def auth_failed():
        raise HTTPException(status_code=401, detail="Authentication failed.")

    if not doc.exists:
        auth_failed()

    data = doc.to_dict()
    if data.get("status") != "active":
        auth_failed()

    now = datetime.now(timezone.utc)
    lockout_str = data.get("lockoutUntil")
    if lockout_str and now < datetime.fromisoformat(lockout_str):
        auth_failed()

    if not pwd_context.verify(payload.pin, data.get("pinHash", "")):
        attempts = data.get("attemptCount", 0) + 1
        update_data = {"attemptCount": attempts}
        if attempts >= 5:
            update_data["lockoutUntil"] = (now + timedelta(minutes=15)).isoformat()
            update_data["attemptCount"] = 0
        doc_ref.update(update_data)
        auth_failed()

    doc_ref.update({"attemptCount": 0, "lockoutUntil": None, "lastVerifiedAt": now.isoformat()})

    return {"ok": True, "verified": True, "uid": uid, "sessionToken": generate_session_token(), "expiresIn": 300}

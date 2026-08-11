import os
import secrets
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, auth, firestore

app = FastAPI()

# Standard CORS policy to ensure the frontend can communicate with the Vercel API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase Admin
# Vercel environments require strict handling of private keys due to newline characters
if not firebase_admin._apps:
    project_id = os.getenv("FIREBASE_PROJECT_ID", "komni-eb72e")
    private_key = os.getenv("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
    client_email = os.getenv("FIREBASE_CLIENT_EMAIL", "")

    if private_key and client_email:
        cred = credentials.Certificate({
            "type": "service_account",
            "project_id": project_id,
            "private_key": private_key,
            "client_email": client_email,
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        firebase_admin.initialize_app(cred)
    else:
        # Fallback for local environments or default service accounts
        firebase_admin.initialize_app()

db = firestore.client()

# --- Schemas ---
class ConfirmRequest(BaseModel):
    confirmed: bool

class VerifyRequest(BaseModel):
    pin: str

# --- Dependencies ---
def get_current_user(authorization: str = Header(None)):
    """Extracts and verifies the Firebase ID token from the Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")
    
    token = authorization.split("Bearer ")[1]
    
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception:
        raise HTTPException(status_code=401, detail="Token verification failed or session expired")

# --- Endpoints ---
PREFIX = "/api/security/auth/pin_guard"

@app.get(f"{PREFIX}/status")
def get_status(uid: str = Depends(get_current_user)):
    """Checks if a user currently has a confirmed PIN established."""
    doc_ref = db.collection("users").document(uid).collection("security").document("pin_guard")
    doc = doc_ref.get()
    
    if doc.exists:
        data = doc.to_dict()
        if data.get("status") == "confirmed":
            return {"provisioned": True, "hasPin": True}
            
    return {"provisioned": False, "hasPin": False}

@app.post(f"{PREFIX}/provision")
def provision_pin(uid: str = Depends(get_current_user)):
    """Generates a cryptographically secure 6-digit PIN and stores only its hash."""
    # Generate secure 6-digit PIN
    pin = f"{secrets.randbelow(1000000):06d}"
    
    # Generate bcrypt hash for Firestore storage
    salt = bcrypt.gensalt()
    hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), salt).decode('utf-8')
    
    doc_ref = db.collection("users").document(uid).collection("security").document("pin_guard")
    doc_ref.set({
        "pin_hash": hashed_pin,
        "status": "provisioned",
        "updated_at": firestore.SERVER_TIMESTAMP
    })
    
    return {"pin": pin}

@app.post(f"{PREFIX}/confirm")
def confirm_pin(req: ConfirmRequest, uid: str = Depends(get_current_user)):
    """Locks in the provisioned PIN once the frontend confirms user has safely copied it."""
    if not req.confirmed:
        raise HTTPException(status_code=400, detail="Confirmation payload missing")
        
    doc_ref = db.collection("users").document(uid).collection("security").document("pin_guard")
    doc = doc_ref.get()
    
    if not doc.exists or doc.to_dict().get("status") != "provisioned":
        raise HTTPException(status_code=400, detail="No PIN is pending confirmation")
        
    doc_ref.update({
        "status": "confirmed",
        "updated_at": firestore.SERVER_TIMESTAMP
    })
    
    return {"confirmed": True, "status": "confirmed", "ok": True}

@app.post(f"{PREFIX}/verify")
def verify_pin(req: VerifyRequest, uid: str = Depends(get_current_user)):
    """Verifies the incoming plaintext PIN against the stored Firestore bcrypt hash."""
    doc_ref = db.collection("users").document(uid).collection("security").document("pin_guard")
    doc = doc_ref.get()
    
    if not doc.exists or doc.to_dict().get("status") != "confirmed":
        raise HTTPException(status_code=401, detail="No active PIN found for this user")
        
    data = doc.to_dict()
    stored_hash = data.get("pin_hash")
    
    # Check if the submitted PIN matches the hash
    if bcrypt.checkpw(req.pin.encode('utf-8'), stored_hash.encode('utf-8')):
        return {"verified": True, "ok": True}
        
    raise HTTPException(status_code=401, detail="Incorrect security PIN")

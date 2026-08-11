import os
import json
import base64
import hashlib
import hmac
import secrets
import re
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Initialize Flask App
app = Flask(__name__)

def init_firebase():
    """Initializes the Firebase Admin SDK using the Vercel Environment Variable."""
    if not firebase_admin._apps:
        sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
        if sa_json:
            try:
                cert_dict = json.loads(sa_json)
                cred = credentials.Certificate(cert_dict)
                firebase_admin.initialize_app(cred)
            except Exception as e:
                print(f"Error initializing Firebase: {e}")

# Call init once when the Vercel serverless environment boots up
init_firebase()

def require_firebase_user(req):
    """
    Validates the Authorization Bearer header securely on the server-side.
    Returns (decoded_token, None) on success, or (None, error_response) on failure.
    """
    if not firebase_admin._apps:
        return None, (jsonify({"ok": False, "message": "Firebase configuration unavailable."}), 503)

    auth_header = req.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, (jsonify({"ok": False, "message": "Missing or malformed Authorization header."}), 401)
    
    token = auth_header.split(" ")[1]
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token, None
    except Exception as e:
        print(f"Firebase auth error: {e}")
        return None, (jsonify({"ok": False, "message": "Invalid, expired, or revoked token."}), 401)

def hash_pin(pin: str, salt: bytes) -> str:
    """Uses scrypt password-based key derivation to securely hash the PIN."""
    derived = hashlib.scrypt(
        pin.encode('utf-8'),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )
    return base64.b64encode(derived).decode('utf-8')

def verify_pin(pin: str, stored_hash_b64: str, salt_b64: str) -> bool:
    """Safely verifies a provided PIN against the stored scrypt hash in constant-time."""
    try:
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(stored_hash_b64)
        derived = hashlib.scrypt(
            pin.encode('utf-8'),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=32
        )
        return hmac.compare_digest(derived, expected_hash)
    except Exception:
        return False

@app.before_request
def handle_preflight():
    """Handles CORS preflight requests securely for the SPA."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

@app.after_request
def add_cors_headers(response):
    """Secures CORS explicitly to the required frontend."""
    response.headers['Access-Control-Allow-Origin'] = 'https://komni.vercel.app'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route("/api/security/auth/pin_guard/status", methods=["GET"])
@app.route("/status", methods=["GET"])
def get_status():
    decoded_token, err_resp = require_firebase_user(request)
    if err_resp: return err_resp
    
    uid = decoded_token.get("uid")
    if not uid:
        return jsonify({"ok": False, "message": "Invalid token payload."}), 401

    try:
        db = firestore.client()
        doc = db.collection("users").document(uid).get()
        
        if not doc.exists:
            return jsonify({"ok": True, "provisioned": False, "confirmed": False, "hasPin": False}), 200
            
        pin_guard = doc.to_dict().get("security", {}).get("pinGuard", {})
        provisioned = bool(pin_guard.get("pinHash"))
        confirmed = bool(pin_guard.get("confirmed"))
        
        return jsonify({
            "ok": True,
            "provisioned": provisioned,
            "confirmed": confirmed,
            "hasPin": provisioned
        }), 200
    except Exception as e:
        print(f"Error in status: {e}")
        return jsonify({"ok": False, "message": "Internal server error."}), 500

@app.route("/api/security/auth/pin_guard/provision", methods=["POST"])
@app.route("/provision", methods=["POST"])
def provision_pin():
    decoded_token, err_resp = require_firebase_user(request)
    if err_resp: return err_resp
    
    uid = decoded_token.get("uid")
    if not uid:
        return jsonify({"ok": False, "message": "Invalid token payload."}), 401

    try:
        db = firestore.client()
        user_ref = db.collection("users").document(uid)
        transaction = db.transaction()
        
        @firestore.transactional
        def do_provision(transaction, ref):
            snapshot = ref.get(transaction=transaction)
            data = snapshot.to_dict() or {}
            pin_guard = data.get("security", {}).get("pinGuard", {})
            
            # Idempotent / concurrent check: fail if hash already exists
            if pin_guard.get("pinHash"):
                return False, {"ok": False, "message": "PIN already provisioned."}
                
            # Secure 6-digit generation
            pin = f"{secrets.randbelow(1000000):06d}"
            salt = secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            pin_hash = hash_pin(pin, salt)
            
            pin_data = {
                "provisioned": True,
                "confirmed": False,
                "pinHash": pin_hash,
                "salt": salt_b64,
                "hashVersion": "scrypt-v1",
                "createdAt": firestore.SERVER_TIMESTAMP,
                "failedAttempts": 0,
                "version": 1
            }
            
            # Deep merge protects existing unrelated user metadata
            transaction.set(ref, {"security": {"pinGuard": pin_data}}, merge=True)
            return True, pin
            
        success, result = do_provision(transaction, user_ref)
        if not success:
            return jsonify(result), 409
            
        print("PIN_PROVISIONED")
        return jsonify({
            "ok": True,
            "provisioned": True,
            "pin": result
        }), 201
    except Exception as e:
        print(f"Error in provision: {e}")
        return jsonify({"ok": False, "message": "Internal server error."}), 500

@app.route("/api/security/auth/pin_guard/confirm", methods=["POST"])
@app.route("/confirm", methods=["POST"])
def confirm_pin():
    decoded_token, err_resp = require_firebase_user(request)
    if err_resp: return err_resp
    
    uid = decoded_token.get("uid")
    if not uid:
        return jsonify({"ok": False, "message": "Invalid token payload."}), 401

    try:
        db = firestore.client()
        user_ref = db.collection("users").document(uid)
        
        doc = user_ref.get()
        if not doc.exists:
            return jsonify({"ok": False, "message": "No PIN has been provisioned."}), 409
            
        pin_guard = doc.to_dict().get("security", {}).get("pinGuard", {})
        
        if not pin_guard.get("pinHash"):
            return jsonify({"ok": False, "message": "No PIN has been provisioned."}), 409
            
        if pin_guard.get("confirmed"):
            return jsonify({"ok": True, "confirmed": True, "status": "confirmed"}), 200
            
        user_ref.set({
            "security": {
                "pinGuard": {
                    "confirmed": True,
                    "confirmedAt": firestore.SERVER_TIMESTAMP
                }
            }
        }, merge=True)
        
        print("PIN_CONFIRMED")
        return jsonify({"ok": True, "confirmed": True, "status": "confirmed"}), 200
    except Exception as e:
        print(f"Error in confirm: {e}")
        return jsonify({"ok": False, "message": "Internal server error."}), 500

@app.route("/api/security/auth/pin_guard/verify", methods=["POST"])
@app.route("/verify", methods=["POST"])
def verify_pin_route():
    decoded_token, err_resp = require_firebase_user(request)
    if err_resp: return err_resp
    
    req_data = request.get_json(silent=True) or {}
    pin = req_data.get("pin")
    
    if not isinstance(pin, str) or not re.match(r"^[0-9]{6}$", pin):
        return jsonify({"ok": False, "message": "Invalid PIN format."}), 400
        
    uid = decoded_token.get("uid")
    if not uid:
        return jsonify({"ok": False, "message": "Invalid token payload."}), 401

    try:
        db = firestore.client()
        user_ref = db.collection("users").document(uid)
        
        doc = user_ref.get()
        if not doc.exists:
            return jsonify({"ok": False, "verified": False, "message": "PIN is not configured."}), 403
            
        pin_guard = doc.to_dict().get("security", {}).get("pinGuard", {})
        
        if not pin_guard.get("confirmed"):
            return jsonify({"ok": False, "verified": False, "message": "PIN is not configured."}), 403
            
        now = datetime.now(timezone.utc)
        locked_until = pin_guard.get("lockedUntil")
        
        # Check brute force state
        if locked_until and isinstance(locked_until, datetime):
            if now < locked_until:
                return jsonify({"ok": False, "verified": False, "message": "PIN verification temporarily locked. Try again later."}), 429
                
        stored_hash = pin_guard.get("pinHash")
        salt_b64 = pin_guard.get("salt")
        
        if not stored_hash or not salt_b64:
             return jsonify({"ok": False, "verified": False, "message": "PIN is not configured."}), 403
        
        if not verify_pin(pin, stored_hash, salt_b64):
            failed_attempts = pin_guard.get("failedAttempts", 0) + 1
            updates = {"security.pinGuard.failedAttempts": failed_attempts}
            
            if failed_attempts >= 5:
                updates["security.pinGuard.lockedUntil"] = now + timedelta(minutes=5)
                print("PIN_LOCKED")
                
            user_ref.update(updates)
            print("PIN_VERIFY_FAILURE")
            return jsonify({"ok": False, "verified": False, "message": "Incorrect PIN."}), 401
            
        # Success - Reset brute force data
        user_ref.update({
            "security.pinGuard.lastVerifiedAt": firestore.SERVER_TIMESTAMP,
            "security.pinGuard.failedAttempts": 0,
            "security.pinGuard.lockedUntil": firestore.DELETE_FIELD
        })
        print("PIN_VERIFY_SUCCESS")
        return jsonify({"ok": True, "verified": True, "message": "PIN verified."}), 200
        
    except Exception as e:
        print(f"Error in verify: {e}")
        return jsonify({"ok": False, "message": "Internal server error."}), 500

d.py


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

# Initialize Flask App & disable strict trailing slashes to prevent 404s
app = Flask(__name__)
app.url_map.strict_slashes = False

def init_firebase():
    """Initialize Firebase Admin once per serverless worker.

    Vercel should provide FIREBASE_SERVICE_ACCOUNT_KEY as the complete service
    account JSON. Base64-encoded JSON is also accepted for environments that
    make multiline secrets awkward.
    """
    if firebase_admin._apps:
        return True

    raw = (os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY") or "").strip()
    if not raw:
        print("FIREBASE_CONFIG_ERROR: FIREBASE_SERVICE_ACCOUNT_KEY is not set")
        return False

    try:
        try:
            cert_dict = json.loads(raw)
        except json.JSONDecodeError:
            cert_dict = json.loads(base64.b64decode(raw).decode("utf-8"))

        if not isinstance(cert_dict, dict) or not cert_dict.get("project_id"):
            raise ValueError("service account JSON is missing project_id")

        cred = credentials.Certificate(cert_dict)
        firebase_admin.initialize_app(cred)
        print("FIREBASE_ADMIN_READY")
        return True
    except Exception as exc:
        print(f"FIREBASE_CONFIG_ERROR: {type(exc).__name__}: {exc}")
        return False


init_firebase()


def allowed_origins():
    configured = os.environ.get("FRONTEND_ORIGINS", "https://komni.vercel.app")
    return {origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()}


@app.before_request
def log_request_info():
    print(f"DEBUG_PATH: {request.path} | METHOD: {request.method}")
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin and origin in allowed_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Max-Age"] = "600"
    return response


@app.route("/health", methods=["GET"])
def health():
    ready = bool(firebase_admin._apps)
    return jsonify({"ok": ready, "firebase": "ready" if ready else "unavailable"}), 200 if ready else 503


def require_firebase_user(req):
    """Verify a Firebase ID token and return its decoded claims."""
    if not firebase_admin._apps:
        return None, (jsonify({"ok": False, "code": "FIREBASE_NOT_CONFIGURED", "message": "Firebase Admin is not configured on the backend."}), 503)

    auth_header = (req.headers.get("Authorization") or "").strip()
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None, (jsonify({"ok": False, "message": "Missing or malformed Authorization header."}), 401)

    try:
        decoded_token = auth.verify_id_token(token.strip(), check_revoked=True)
        return decoded_token, None
    except auth.RevokedIdTokenError:
        return None, (jsonify({"ok": False, "message": "Session token has been revoked. Sign in again."}), 401)
    except Exception as exc:
        print(f"Firebase auth error: {type(exc).__name__}: {exc}")
        return None, (jsonify({"ok": False, "message": "Invalid or expired authentication token."}), 401)


def hash_pin(pin: str, salt: bytes) -> str:
    derived = hashlib.scrypt(pin.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
    return base64.b64encode(derived).decode('utf-8')

def verify_pin(pin: str, stored_hash_b64: str, salt_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(stored_hash_b64)
        derived = hashlib.scrypt(pin.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(derived, expected_hash)
    except Exception:
        return False

# --- ROUTES (Aliased for all possible Vercel routing prefixes) ---

@app.route("/api/security/auth/pin_guard/status", methods=["GET"])
@app.route("/status", methods=["GET"])
@app.route("/pin_guard/status", methods=["GET"])
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
@app.route("/pin_guard/provision", methods=["POST"])
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
            
            if pin_guard.get("pinHash"):
                return False, {"ok": False, "message": "PIN already provisioned."}
                
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
            
            transaction.set(ref, {"security": {"pinGuard": pin_data}}, merge=True)
            return True, pin
            
        success, result = do_provision(transaction, user_ref)
        if not success:
            return jsonify(result), 409
            
        print("PIN_PROVISIONED")
        return jsonify({"ok": True, "provisioned": True, "pin": result}), 201
    except Exception as e:
        print(f"Error in provision: {e}")
        return jsonify({"ok": False, "message": "Internal server error."}), 500

@app.route("/api/security/auth/pin_guard/confirm", methods=["POST"])
@app.route("/confirm", methods=["POST"])
@app.route("/pin_guard/confirm", methods=["POST"])
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
@app.route("/pin_guard/verify", methods=["POST"])
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
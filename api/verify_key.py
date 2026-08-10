import os
import json
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

cors_origins = os.environ.get("CORS_ORIGINS", "*")

if cors_origins == "*":
    CORS(app)
else:
    CORS(
        app,
        origins=[
            origin.strip()
            for origin in cors_origins.split(",")
            if origin.strip()
        ],
        methods=["POST", "GET", "OPTIONS"],
        allow_headers=["Content-Type"],
    )


# ============================================================
# CONFIGURATION
# ============================================================

ISSUANCE_COLLECTION = "issuance_keys"
AUTH_EVENT_COLLECTION = "issuance_auth_events"

# IMPORTANT:
# This is intentionally server-side. It is never sent to login.html.
# Add future issuance keys here as they are issued.
ISSUANCE_KEYS = {
    "ik-010101": {
        "owner": "KOMNI Sandbox Client",
        "business_id": "biz_komni_sandbox",
        "workspace_id": "workspace_komni_sandbox",
        "tier": "Development Node",
        "key_type": "Test Environment Key",
        "environment": "test",
    }
}


# ============================================================
# FIREBASE ADMIN INITIALIZATION
# ============================================================

def get_firebase_app():
    """
    Initialize Firebase Admin once per warm Vercel execution.

    Required Vercel environment variable:

        FIREBASE_SERVICE_ACCOUNT_JSON

    It must contain the Firebase Admin service-account JSON object.
    The private service-account JSON stays server-side and is never
    exposed to the browser.
    """

    if firebase_admin._apps:
        return firebase_admin.get_app()

    raw_credentials = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

    if not raw_credentials:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not configured."
        )

    try:
        service_account_info = json.loads(raw_credentials)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON contains invalid JSON."
        ) from exc

    try:
        credential = credentials.Certificate(service_account_info)

        return firebase_admin.initialize_app(credential)

    except Exception as exc:
        raise RuntimeError(
            "Firebase Admin initialization failed."
        ) from exc


def get_db():
    get_firebase_app()
    return firestore.client()


# ============================================================
# ISSUANCE KEY NORMALIZATION / HASHING
# ============================================================

def normalize_issuance_key(raw_key):
    """
    Canonical representation.

    ik-010101
    IK-010101
    ik_010101

    all become:

    ik_010101
    """

    if not isinstance(raw_key, str):
        return ""

    return (
        raw_key
        .strip()
        .lower()
        .replace("-", "_")
    )


def hash_issuance_key(raw_key):
    normalized = normalize_issuance_key(raw_key)

    if not normalized:
        return ""

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def find_server_key(raw_key):
    """
    Compare the submitted key against the server-side issuance
    registry. The plaintext key is never returned to the client.
    """

    normalized = normalize_issuance_key(raw_key)

    for configured_key, metadata in ISSUANCE_KEYS.items():
        if normalize_issuance_key(configured_key) == normalized:
            return configured_key, metadata

    return None, None


# ============================================================
# FIRESTORE REGISTRY
# ============================================================

def save_issuance_registry(key, metadata):
    """
    Upsert the verified issuance key's server-side registry record.

    Firestore stores the SHA-256 key hash rather than the plaintext
    issuance key.
    """

    db = get_db()

    normalized = normalize_issuance_key(key)
    key_hash = hash_issuance_key(normalized)

    if not key_hash:
        raise RuntimeError("Unable to hash issuance key.")

    # Stable document ID derived from the canonical key.
    document_id = key_hash[:32]

    document_ref = (
        db.collection(ISSUANCE_COLLECTION)
        .document(document_id)
    )

    now = firestore.SERVER_TIMESTAMP

    document_ref.set(
        {
            "key_hash": key_hash,
            "owner": metadata["owner"],
            "business_id": metadata["business_id"],
            "workspace_id": metadata["workspace_id"],
            "tier": metadata["tier"],
            "key_type": metadata["key_type"],
            "environment": metadata["environment"],
            "status": "active",
            "source": "server_hardcoded_registry",
            "updated_at": now,
        },
        merge=True,
    )

    return document_id


def save_auth_event(key, metadata, issuance_document_id):
    """
    Save an audit event for the successful login.

    The raw issuance key is intentionally not stored.
    """

    db = get_db()

    key_hash = hash_issuance_key(key)

    event_ref = db.collection(AUTH_EVENT_COLLECTION).document()

    event_ref.set(
        {
            "issuance_key_hash": key_hash,
            "issuance_key_id": issuance_document_id,
            "owner": metadata["owner"],
            "business_id": metadata["business_id"],
            "workspace_id": metadata["workspace_id"],
            "environment": metadata["environment"],
            "event": "issuance_key_verified",
            "created_at": firestore.SERVER_TIMESTAMP,
        }
    )

    return event_ref.id


# ============================================================
# SAFE RESPONSES
# ============================================================

def authorization_failure():
    return jsonify({
        "valid": False,
        "reason": "Unrecognized or revoked Enterprise Issuance Key."
    }), 401


def build_safe_metadata(document_id, metadata):
    """
    Safe data that login.html can receive.

    Never expose:
      - raw issuance key
      - key hash
      - Firebase service account
      - private credentials
    """

    return {
        "issuance_key_id": document_id,
        "owner": metadata.get("owner", ""),
        "business_id": metadata.get("business_id", ""),
        "workspace_id": metadata.get("workspace_id", ""),
        "tier": metadata.get("tier", ""),
        "key_type": metadata.get("key_type", ""),
        "environment": metadata.get("environment", "test"),
        "status": "active",
    }


# ============================================================
# VERIFY ISSUANCE KEY
# ============================================================

@app.route("/", methods=["POST", "OPTIONS"])
@app.route("/api/verify_key", methods=["POST", "OPTIONS"])
def verify_key():

    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "valid": False,
            "reason": "Request body must be a JSON object."
        }), 400

    raw_key = data.get("key")

    if not isinstance(raw_key, str):
        return jsonify({
            "valid": False,
            "reason": "Missing required field: key"
        }), 400

    raw_key = raw_key.strip()

    if not raw_key:
        return jsonify({
            "valid": False,
            "reason": "Missing required field: key"
        }), 400

    if len(raw_key) > 512:
        return authorization_failure()

    normalized_key = normalize_issuance_key(raw_key)

    if not normalized_key.startswith("ik_"):
        return authorization_failure()

    # --------------------------------------------------------
    # SERVER-SIDE ISSUANCE REGISTRY CHECK
    # --------------------------------------------------------

    configured_key, metadata = find_server_key(raw_key)

    if not configured_key or not metadata:
        return authorization_failure()

    if metadata.get("environment") not in ("test", "production"):
        print("[verify_key] invalid environment for configured key")
        return jsonify({
            "valid": False,
            "reason": "Authorization service temporarily unavailable."
        }), 503

    if not metadata.get("business_id") or not metadata.get("workspace_id"):
        print("[verify_key] incomplete server issuance metadata")
        return jsonify({
            "valid": False,
            "reason": "Authorization service temporarily unavailable."
        }), 503

    # --------------------------------------------------------
    # FIRESTORE WRITE
    # --------------------------------------------------------

    try:
        issuance_document_id = save_issuance_registry(
            configured_key,
            metadata,
        )

        auth_event_id = save_auth_event(
            configured_key,
            metadata,
            issuance_document_id,
        )

    except Exception as exc:
        print(
            "[verify_key] Firestore authorization write error:",
            repr(exc)
        )

        return jsonify({
            "valid": False,
            "reason": "Authorization service temporarily unavailable."
        }), 503

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    safe_metadata = build_safe_metadata(
        issuance_document_id,
        metadata,
    )

    return jsonify({
        "valid": True,
        "message": "Issuance key verified and session recorded.",
        "metadata": safe_metadata,
        "firestore": {
            "saved": True,
            "issuance_record": True,
            "auth_event": True,
            "auth_event_id": auth_event_id,
        },
    }), 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
@app.route("/api/verify_key", methods=["GET"])
def health():

    return jsonify({
        "ok": True,
        "service": "KOMNI Enterprise Issuance Authorization",
        "endpoint": "/api/verify_key",
        "database": "firestore",
        "configured_issuance_keys": len(ISSUANCE_KEYS),
    }), 200


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False,
    )

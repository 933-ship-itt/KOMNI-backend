import os
import json
import hashlib

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


app = Flask(__name__)
CORS(app)


# =========================================================
# DEVELOPMENT BOOTSTRAP CONFIG
# =========================================================

# Development-only issuance key.
#
# IMPORTANT:
# This should NOT be used in production.
# It exists so the KOMNI development workspace can bootstrap
# its first Firestore issuance record automatically.
DEV_ISSUANCE_KEY = "ik_test_demo"

DEV_ISSUANCE_METADATA = {
    "owner": "KOMNI Sandbox Client",
    "business_id": "biz_komni_sandbox",
    "workspace_id": "workspace_komni_sandbox",
    "tier": "Development Node",
    "key_type": "Test Environment Key",
    "status": "active"
}


# =========================================================
# FIREBASE ADMIN
# =========================================================

def get_firebase_app():
    """
    Initialize Firebase Admin once.

    Required Vercel environment variable:

        FIREBASE_SERVICE_ACCOUNT_JSON

    This must contain the Firebase Admin service-account JSON.
    """

    if firebase_admin._apps:
        return firebase_admin.get_app()

    service_account_json = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not service_account_json:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON environment variable is missing."
        )

    try:
        service_account_info = json.loads(service_account_json)
    except json.JSONDecodeError:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON contains invalid JSON."
        )

    credential = credentials.Certificate(service_account_info)

    return firebase_admin.initialize_app(credential)


def get_db():
    get_firebase_app()
    return firestore.client()


# =========================================================
# ISSUANCE KEY HELPERS
# =========================================================

def normalize_issuance_key(raw_key):
    """
    Normalize:

        IK-TEST-DEMO
        ik-test-demo
        ik_test_demo

    into:

        ik_test_demo
    """

    if not isinstance(raw_key, str):
        return ""

    return (
        raw_key
        .strip()
        .lower()
        .replace("ik-", "ik_")
    )


def hash_issuance_key(raw_key):
    """
    Hash the normalized issuance key.

    The plaintext issuance key is never stored in Firestore.
    """

    normalized = normalize_issuance_key(raw_key)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# =========================================================
# DEVELOPMENT FIRESTORE BOOTSTRAP
# =========================================================

def ensure_dev_issuance_key():
    """
    Ensure the development issuance key exists in Firestore.

    This allows:

        ik-test-demo

    to automatically create its Firestore record the first
    time the endpoint is used.

    This function is intentionally limited to the development
    key and should not be used as the production provisioning
    mechanism.
    """

    db = get_db()

    key_hash = hash_issuance_key(DEV_ISSUANCE_KEY)

    collection = db.collection("issuance_keys")

    query = (
        collection
        .where("key_hash", "==", key_hash)
        .limit(1)
        .stream()
    )

    existing = next(query, None)

    if existing:
        return existing.id, existing.to_dict() or {}

    document_id = "ik_test_demo"

    document_data = {
        "key_hash": key_hash,
        **DEV_ISSUANCE_METADATA,
        "source": "development_bootstrap",
    }

    collection.document(document_id).set(document_data)

    return document_id, document_data


# =========================================================
# FIRESTORE LOOKUP
# =========================================================

def find_issuance_key(raw_key):
    """
    Find an issuance key by its SHA-256 hash.
    """

    db = get_db()

    key_hash = hash_issuance_key(raw_key)

    query = (
        db.collection("issuance_keys")
        .where("key_hash", "==", key_hash)
        .limit(1)
        .stream()
    )

    for document in query:
        return {
            "document_id": document.id,
            "data": document.to_dict() or {}
        }

    return None


# =========================================================
# VERIFY ISSUANCE KEY
# =========================================================

@app.route(
    "/",
    defaults={"path": ""},
    methods=["POST", "OPTIONS"]
)
@app.route(
    "/<path:path>",
    methods=["POST", "OPTIONS"]
)
def verify_key(path):

    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}

    raw_key = data.get("key", "")

    if not isinstance(raw_key, str) or not raw_key.strip():
        return jsonify({
            "valid": False,
            "reason": "Missing required field: key"
        }), 400

    normalized_key = normalize_issuance_key(raw_key)

    if not normalized_key.startswith("ik_"):
        return jsonify({
            "valid": False,
            "reason": "Invalid Enterprise Issuance Key format."
        }), 401

    try:

        # -------------------------------------------------
        # Development bootstrap
        # -------------------------------------------------
        #
        # If the user provides the development key,
        # make sure its Firestore record exists.
        #
        if normalized_key == DEV_ISSUANCE_KEY:
            ensure_dev_issuance_key()

        # -------------------------------------------------
        # Normal Firestore authorization
        # -------------------------------------------------

        matched = find_issuance_key(normalized_key)

        if not matched:
            return jsonify({
                "valid": False,
                "reason": (
                    "Unrecognized or revoked "
                    "Enterprise Issuance Key."
                )
            }), 401

        metadata = matched["data"]

        # -------------------------------------------------
        # Status enforcement
        # -------------------------------------------------

        if metadata.get("status") != "active":
            return jsonify({
                "valid": False,
                "reason": (
                    "Unrecognized or revoked "
                    "Enterprise Issuance Key."
                )
            }), 401

        # -------------------------------------------------
        # Only return safe metadata
        # -------------------------------------------------

        safe_metadata = {
            "owner": metadata.get("owner", ""),
            "business_id": metadata.get("business_id", ""),
            "workspace_id": metadata.get("workspace_id", ""),
            "tier": metadata.get("tier", ""),
            "key_type": metadata.get("key_type", ""),
            "status": "active"
        }

        return jsonify({
            "valid": True,
            "message": "Signature verified successfully.",
            "metadata": safe_metadata
        }), 200

    except Exception as exc:

        # Do not expose Firebase credentials,
        # Firestore internals, or stack traces.
        print(f"verify_key error: {exc}")

        return jsonify({
            "valid": False,
            "reason": (
                "Authorization service temporarily unavailable."
            )
        }), 500


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/", methods=["GET"])
def health():

    return jsonify({
        "ok": True,
        "endpoint": "/api/verify_key",
        "service": "KOMNI Enterprise Issuance Authorization",
        "database": "firestore",
        "development_bootstrap": True
    }), 200


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=True
    )

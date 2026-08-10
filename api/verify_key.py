import os
import json
import hashlib

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


app = Flask(__name__)
CORS(app)


# ---------------------------------------------------------
# Firebase Admin initialization
# ---------------------------------------------------------

def get_firebase_app():
    """
    Initialize Firebase Admin exactly once.

    Vercel should have a FIREBASE_SERVICE_ACCOUNT_JSON
    environment variable containing the Firebase Admin
    service-account JSON.
    """
    if firebase_admin._apps:
        return firebase_admin.get_app()

    service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

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
    firebase_app = get_firebase_app()
    return firestore.client(app=firebase_app)


# ---------------------------------------------------------
# Issuance key helpers
# ---------------------------------------------------------

def normalize_issuance_key(raw_key):
    """
    Normalize the issuance key in the same way your existing
    endpoint did.

    Example:
        IK-010101
        ik-010101
        ik_010101

    all become:
        ik_010101
    """
    if not isinstance(raw_key, str):
        return ""

    return raw_key.strip().lower().replace("ik-", "ik_")


def hash_issuance_key(raw_key):
    """
    Store only a SHA-256 hash of the issuance key in Firestore.
    The raw key itself is never stored.
    """
    normalized = normalize_issuance_key(raw_key)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# Firestore lookup
# ---------------------------------------------------------

def find_issuance_key(raw_key):
    """
    Locate an issuance key by its SHA-256 hash.

    Firestore structure:

    issuance_keys/
        {document_id}
            key_hash
            owner
            business_id
            workspace_id
            tier
            key_type
            status
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
        data = document.to_dict() or {}

        return {
            "document_id": document.id,
            "data": data,
        }

    return None


# ---------------------------------------------------------
# API
# ---------------------------------------------------------

@app.route("/", defaults={"path": ""}, methods=["POST", "OPTIONS"])
@app.route("/<path:path>", methods=["POST", "OPTIONS"])
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

    # Issuance keys must have the expected format.
    if not normalized_key.startswith("ik_"):
        return jsonify({
            "valid": False,
            "reason": "Invalid Enterprise Issuance Key format."
        }), 401

    try:
        matched = find_issuance_key(normalized_key)

        if not matched:
            return jsonify({
                "valid": False,
                "reason": "Unrecognized or revoked Enterprise Issuance Key."
            }), 401

        metadata = matched["data"]

        # -------------------------------------------------
        # Status enforcement
        # -------------------------------------------------

        if metadata.get("status") != "active":
            return jsonify({
                "valid": False,
                "reason": "Unrecognized or revoked Enterprise Issuance Key."
            }), 401

        # -------------------------------------------------
        # Return only non-sensitive metadata
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
        # Never expose Firebase credentials, database details,
        # or internal exception information to the browser.
        print(f"verify_key error: {exc}")

        return jsonify({
            "valid": False,
            "reason": "Authorization service temporarily unavailable."
        }), 500


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "endpoint": "/api/verify_key",
        "service": "KOMNI Enterprise Issuance Authorization",
        "database": "firestore"
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=True
    )

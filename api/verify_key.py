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
# DEVELOPMENT CONFIG
# =========================================================

DEV_ISSUANCE_KEY = "ik_test_demo"

DEV_ISSUANCE_METADATA = {
    "owner": "KOMNI Sandbox Client",
    "business_id": "biz_komni_sandbox",
    "workspace_id": "workspace_komni_sandbox",
    "tier": "Development Node",
    "key_type": "Test Environment Key",
    "status": "active",
}


# =========================================================
# FIREBASE
# =========================================================

def get_firebase_app():

    if firebase_admin._apps:
        return firebase_admin.get_app()

    service_account_json = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not service_account_json:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not configured."
        )

    service_account_info = json.loads(service_account_json)

    credential = credentials.Certificate(
        service_account_info
    )

    return firebase_admin.initialize_app(credential)


def get_db():
    get_firebase_app()
    return firestore.client()


# =========================================================
# KEY HELPERS
# =========================================================

def normalize_issuance_key(raw_key):

    if not isinstance(raw_key, str):
        return ""

    value = raw_key.strip().lower()

    # Accept all of these:
    #
    # ik-test-demo
    # ik_test_demo
    # IK-TEST-DEMO
    # IK_TEST_DEMO

    if value.startswith("ik-"):
        value = "ik_" + value[3:]

    return value


def hash_issuance_key(raw_key):

    normalized = normalize_issuance_key(raw_key)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# =========================================================
# DEVELOPMENT BOOTSTRAP
# =========================================================

def ensure_dev_key():

    db = get_db()

    key_hash = hash_issuance_key(
        DEV_ISSUANCE_KEY
    )

    document_ref = (
        db.collection("issuance_keys")
        .document("ik_test_demo")
    )

    document = document_ref.get()

    if not document.exists:

        document_ref.set({
            "key_hash": key_hash,
            **DEV_ISSUANCE_METADATA,
            "source": "development_bootstrap",
        })

    return document_ref.get().to_dict()


# =========================================================
# LOOKUP
# =========================================================

def find_issuance_key(raw_key):

    db = get_db()

    key_hash = hash_issuance_key(raw_key)

    results = (
        db.collection("issuance_keys")
        .where(
            "key_hash",
            "==",
            key_hash
        )
        .limit(1)
        .stream()
    )

    for document in results:

        return document.to_dict()

    return None


# =========================================================
# VERIFY
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

    normalized_key = normalize_issuance_key(
        raw_key
    )

    print(
        f"VERIFY KEY: raw={raw_key!r}, "
        f"normalized={normalized_key!r}"
    )

    # -----------------------------------------------------
    # DEVELOPMENT KEY
    # -----------------------------------------------------

    if normalized_key == DEV_ISSUANCE_KEY:

        try:

            # This creates the Firestore record if necessary.
            metadata = ensure_dev_key()

            return jsonify({
                "valid": True,
                "message": "Development issuance key verified.",
                "metadata": {
                    "owner": metadata.get("owner"),
                    "business_id": metadata.get("business_id"),
                    "workspace_id": metadata.get("workspace_id"),
                    "tier": metadata.get("tier"),
                    "key_type": metadata.get("key_type"),
                    "status": metadata.get("status"),
                }
            }), 200

        except Exception as exc:

            print(
                f"Development key bootstrap error: {exc}"
            )

            return jsonify({
                "valid": False,
                "reason": "Authorization service temporarily unavailable."
            }), 500

    # -----------------------------------------------------
    # NORMAL ISSUANCE KEYS
    # -----------------------------------------------------

    if not normalized_key.startswith("ik_"):

        return jsonify({
            "valid": False,
            "reason": "Invalid Enterprise Issuance Key format."
        }), 401

    try:

        metadata = find_issuance_key(
            normalized_key
        )

        if not metadata:

            return jsonify({
                "valid": False,
                "reason": "Unrecognized or revoked Enterprise Issuance Key."
            }), 401

        if metadata.get("status") != "active":

            return jsonify({
                "valid": False,
                "reason": "Unrecognized or revoked Enterprise Issuance Key."
            }), 401

        return jsonify({
            "valid": True,
            "message": "Signature verified successfully.",
            "metadata": {
                "owner": metadata.get("owner", ""),
                "business_id": metadata.get("business_id", ""),
                "workspace_id": metadata.get("workspace_id", ""),
                "tier": metadata.get("tier", ""),
                "key_type": metadata.get("key_type", ""),
                "status": "active",
            }
        }), 200

    except Exception as exc:

        print(
            f"verify_key Firestore error: {exc}"
        )

        return jsonify({
            "valid": False,
            "reason": "Authorization service temporarily unavailable."
        }), 500


# =========================================================
# HEALTH
# =========================================================

@app.route("/", methods=["GET"])
def health():

    return jsonify({
        "ok": True,
        "endpoint": "/api/verify_key",
        "service": "KOMNI Enterprise Issuance Authorization",
        "database": "firestore",
        "development_key_enabled": True,
    }), 200


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=True
    )

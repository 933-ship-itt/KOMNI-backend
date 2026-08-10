import os
import json
import hashlib
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


app = Flask(__name__)
CORS(app)


# ============================================================
# DEVELOPMENT TEST CONFIG
# ============================================================

DEV_KEY = "ik_test_demo"
DEV_DOCUMENT_ID = "ik_test_demo"


# ============================================================
# RESPONSE HELPERS
# ============================================================

def success(stage, **extra):
    return jsonify({
        "ok": True,
        "stage": stage,
        **extra
    }), 200


def failure(stage, message, status=500):
    return jsonify({
        "ok": False,
        "stage": stage,
        "reason": message
    }), status


# ============================================================
# KEY HELPERS
# ============================================================

def normalize_key(value):
    if not isinstance(value, str):
        return ""

    value = value.strip().lower()

    if value.startswith("ik-"):
        value = "ik_" + value[3:]

    return value


def hash_key(value):
    normalized = normalize_key(value)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# ============================================================
# FIREBASE INITIALIZATION
# ============================================================

def firebase_status():

    # Firebase Admin already initialized
    if firebase_admin._apps:
        firebase_app = firebase_admin.get_app()

        return {
            "initialized": True,
            "project_id": firebase_app.project_id
        }

    raw = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not raw:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is missing from Vercel environment variables."
        )

    try:
        service_account = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON exists but is not valid JSON."
        )

    if not isinstance(service_account, dict):
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON must contain a JSON object."
        )

    required = [
        "type",
        "project_id",
        "private_key",
        "client_email"
    ]

    missing = [
        field
        for field in required
        if not service_account.get(field)
    ]

    if missing:
        raise RuntimeError(
            "Firebase service account is missing required fields: "
            + ", ".join(missing)
        )

    credential = credentials.Certificate(
        service_account
    )

    firebase_app = firebase_admin.initialize_app(
        credential
    )

    return {
        "initialized": True,
        "project_id": firebase_app.project_id
    }


def get_db():

    firebase_status()

    return firestore.client()


# ============================================================
# FIRESTORE DEVELOPMENT TEST
# ============================================================

def bootstrap_test_document():

    db = get_db()

    key_hash = hash_key(DEV_KEY)

    document_ref = (
        db.collection("issuance_keys")
        .document(DEV_DOCUMENT_ID)
    )

    document_data = {
        "key_hash": key_hash,
        "owner": "KOMNI Sandbox Client",
        "business_id": "biz_komni_sandbox",
        "workspace_id": "workspace_komni_sandbox",
        "tier": "Development Node",
        "key_type": "Test Environment Key",
        "status": "active",
        "source": "verify_key_diagnostic",
    }

    # --------------------------------------------------------
    # WRITE TEST
    # --------------------------------------------------------

    document_ref.set(
        document_data
    )

    # --------------------------------------------------------
    # READ TEST
    # --------------------------------------------------------

    snapshot = document_ref.get()

    if not snapshot.exists:

        raise RuntimeError(
            "Firestore write completed but the document could not be read back."
        )

    saved = snapshot.to_dict() or {}

    if saved.get("key_hash") != key_hash:

        raise RuntimeError(
            "Firestore document exists but key_hash does not match."
        )

    return {
        "document_path": (
            f"issuance_keys/{DEV_DOCUMENT_ID}"
        ),
        "document_exists": True,
        "status": saved.get("status"),
        "project_id": (
            firebase_admin.get_app().project_id
        )
    }


# ============================================================
# HEALTH / DIAGNOSTIC ENDPOINT
# ============================================================

@app.route("/", methods=["GET"])
def health():

    # Stage 1 — Python function loaded
    result = {
        "service": "KOMNI verify_key diagnostic",
        "deployment": "diagnostic-v1",
        "python_loaded": True,
        "firebase_admin_imported": True,
    }

    # Stage 2 — Firebase initialization
    try:

        firebase = firebase_status()

        result["firebase_initialized"] = True
        result["firebase_project_id"] = firebase["project_id"]

    except Exception:

        result["firebase_initialized"] = False
        result["firebase_project_id"] = None

        return failure(
            "firebase_initialization",
            "Firebase Admin initialization failed.",
            500
        )

    # Stage 3 — Firestore connectivity
    try:

        db = get_db()

        # A harmless read of the collection.
        #
        # We don't expose any returned documents.
        list(
            db.collection("issuance_keys")
            .limit(1)
            .stream()
        )

        result["firestore_reachable"] = True

    except Exception:

        result["firestore_reachable"] = False

        return failure(
            "firestore_connectivity",
            "Firestore could not be reached.",
            500
        )

    return success(
        "all_systems_ready",
        **result
    )


# ============================================================
# VERIFY ISSUANCE KEY
# ============================================================

@app.route(
    "/",
    methods=["POST", "OPTIONS"]
)
def verify_key():

    if request.method == "OPTIONS":
        return "", 200

    # --------------------------------------------------------
    # Stage 1 — Parse JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return failure(
            "request_parsing",
            "Request body must be valid JSON.",
            400
        )

    raw_key = data.get("key")

    if not isinstance(raw_key, str):

        return failure(
            "request_validation",
            "Missing required field: key.",
            400
        )

    normalized = normalize_key(
        raw_key
    )

    if not normalized:

        return failure(
            "request_validation",
            "The supplied key is empty.",
            400
        )

    # --------------------------------------------------------
    # Stage 2 — Verify normalization
    # --------------------------------------------------------

    if normalized != DEV_KEY:

        return failure(
            "key_matching",
            "Diagnostic endpoint only accepts ik-test-demo.",
            401
        )

    # --------------------------------------------------------
    # Stage 3 — Firebase + Firestore
    # --------------------------------------------------------

    try:

        firebase = firebase_status()

    except Exception as exc:

        print(
            "Firebase initialization error:",
            repr(exc)
        )

        return failure(
            "firebase_initialization",
            "Firebase Admin initialization failed.",
            500
        )

    try:

        firestore_result = bootstrap_test_document()

    except Exception as exc:

        print(
            "Firestore diagnostic error:",
            repr(exc)
        )

        # Full traceback stays in Vercel logs,
        # never in the HTTP response.
        traceback.print_exc()

        return failure(
            "firestore_operation",
            "Firestore write/read test failed.",
            500
        )

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    return success(
        "issuance_key_verified",
        valid=True,
        message="Development issuance key verified successfully.",
        metadata={
            "owner": "KOMNI Sandbox Client",
            "business_id": "biz_komni_sandbox",
            "workspace_id": "workspace_komni_sandbox",
            "tier": "Development Node",
            "key_type": "Test Environment Key",
            "status": "active"
        },
        diagnostic={
            "normalized_key": normalized,
            "firestore": firestore_result,
            "firebase_project_id": firebase["project_id"]
        }
    )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                8000
            )
        ),
        debug=True
    )

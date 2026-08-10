import os
import json
import hashlib
import secrets
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

# For production, set CORS_ORIGINS in Vercel to your actual
# frontend origin(s), comma-separated.
#
# Example:
# CORS_ORIGINS=https://komni.com,https://www.komni.com
#
# During development, "*" is allowed as a fallback.
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

# Development bootstrap is OFF unless explicitly enabled.
#
# In Vercel, for your development environment:
#
# ENABLE_DEV_BOOTSTRAP=true
#
# Do NOT enable this in a real production environment.
ENABLE_DEV_BOOTSTRAP = (
    os.environ.get(
        "ENABLE_DEV_BOOTSTRAP",
        "false"
    ).strip().lower()
    == "true"
)

DEV_ISSUANCE_KEY = os.environ.get(
    "DEV_ISSUANCE_KEY",
    "ik_test_demo"
)

DEV_ISSUANCE_METADATA = {
    "owner": "KOMNI Sandbox Client",
    "business_id": "biz_komni_sandbox",
    "workspace_id": "workspace_komni_sandbox",
    "tier": "Development Node",
    "key_type": "Test Environment Key",
}


# ============================================================
# FIREBASE ADMIN INITIALIZATION
# ============================================================

def get_firebase_app():
    """
    Initialize Firebase Admin exactly once per serverless
    execution environment.

    Required Vercel environment variable:

        FIREBASE_SERVICE_ACCOUNT_JSON

    The value must contain the Firebase Admin service-account
    JSON object.
    """

    if firebase_admin._apps:
        return firebase_admin.get_app()

    raw_credentials = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not raw_credentials:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not configured."
        )

    try:
        service_account_info = json.loads(
            raw_credentials
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON contains invalid JSON."
        ) from exc

    try:
        credential = credentials.Certificate(
            service_account_info
        )

        return firebase_admin.initialize_app(
            credential
        )

    except Exception as exc:
        raise RuntimeError(
            "Firebase Admin initialization failed."
        ) from exc


def get_db():
    """
    Return the Firestore client.
    """

    get_firebase_app()

    return firestore.client()


# ============================================================
# ISSUANCE KEY NORMALIZATION
# ============================================================

def normalize_issuance_key(raw_key):
    """
    Convert accepted presentation forms to one canonical form.

    Examples:

        IK-TEST-DEMO
        ik-test-demo
        ik_test_demo

    all become:

        ik_test_demo
    """

    if not isinstance(raw_key, str):
        return ""

    return (
        raw_key
        .strip()
        .lower()
        .replace("-", "_")
    )


# ============================================================
# KEY HASHING
# ============================================================

def hash_issuance_key(raw_key):
    """
    Hash the canonical issuance key.

    Plaintext issuance keys are never written to Firestore.
    """

    normalized = normalize_issuance_key(
        raw_key
    )

    if not normalized:
        return ""

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# ============================================================
# SAFE ERROR RESPONSE
# ============================================================

def authorization_failure(
    reason="Unrecognized or revoked Enterprise Issuance Key."
):
    """
    Keep authorization failures intentionally generic.

    We do not tell a caller whether:
      - the key exists,
      - the key is revoked,
      - the key belongs to another workspace,
      - Firestore contains a matching hash.

    This prevents authorization enumeration.
    """

    return jsonify({
        "valid": False,
        "reason": reason
    }), 401


# ============================================================
# FIRESTORE DEVELOPMENT BOOTSTRAP
# ============================================================

def ensure_development_issuance_key():
    """
    Development-only helper.

    When ENABLE_DEV_BOOTSTRAP=true, the development issuance
    key is created in Firestore if it does not already exist.

    This is deliberately disabled by default.
    """

    if not ENABLE_DEV_BOOTSTRAP:
        return None

    normalized_key = normalize_issuance_key(
        DEV_ISSUANCE_KEY
    )

    key_hash = hash_issuance_key(
        normalized_key
    )

    if not key_hash:
        raise RuntimeError(
            "Development issuance key is invalid."
        )

    db = get_db()

    collection = db.collection(
        ISSUANCE_COLLECTION
    )

    # Use a deterministic document ID for the development
    # bootstrap record.
    document_ref = collection.document(
        "ik_test_demo"
    )

    snapshot = document_ref.get()

    if snapshot.exists:
        return {
            "document_id": document_ref.id,
            "data": snapshot.to_dict() or {}
        }

    document_data = {
        "key_hash": key_hash,

        "owner":
            DEV_ISSUANCE_METADATA["owner"],

        "business_id":
            DEV_ISSUANCE_METADATA["business_id"],

        "workspace_id":
            DEV_ISSUANCE_METADATA["workspace_id"],

        "tier":
            DEV_ISSUANCE_METADATA["tier"],

        "key_type":
            DEV_ISSUANCE_METADATA["key_type"],

        "status":
            "active",

        "environment":
            "test",

        "source":
            "development_bootstrap",

        "created_at":
            firestore.SERVER_TIMESTAMP,

        "updated_at":
            firestore.SERVER_TIMESTAMP,
    }

    document_ref.set(
        document_data
    )

    return {
        "document_id": document_ref.id,
        "data": document_data
    }


# ============================================================
# FIRESTORE KEY LOOKUP
# ============================================================

def find_issuance_key(raw_key):
    """
    Find an issuance key by its SHA-256 hash.

    Firestore stores only the hash, never the plaintext key.
    """

    key_hash = hash_issuance_key(
        raw_key
    )

    if not key_hash:
        return None

    db = get_db()

    query = (
        db.collection(
            ISSUANCE_COLLECTION
        )
        .where(
            "key_hash",
            "==",
            key_hash
        )
        .limit(1)
        .stream()
    )

    for document in query:

        return {
            "document_id":
                document.id,

            "data":
                document.to_dict() or {}
        }

    return None


# ============================================================
# SAFE METADATA
# ============================================================

def build_safe_metadata(
    document_id,
    metadata
):
    """
    Only return fields that login.html needs or that are
    safe for a browser session to know.

    Never return:
        key_hash
        service-account data
        Stripe secret keys
        internal credentials
    """

    return {
        "issuance_key_id":
            document_id,

        "owner":
            metadata.get(
                "owner",
                ""
            ),

        "business_id":
            metadata.get(
                "business_id",
                ""
            ),

        "workspace_id":
            metadata.get(
                "workspace_id",
                ""
            ),

        "tier":
            metadata.get(
                "tier",
                ""
            ),

        "key_type":
            metadata.get(
                "key_type",
                ""
            ),

        "environment":
            metadata.get(
                "environment",
                "test"
            ),

        "status":
            "active",
    }


# ============================================================
# VERIFY ISSUANCE KEY
# ============================================================

@app.route(
    "/",
    methods=[
        "POST",
        "OPTIONS"
    ]
)
@app.route(
    "/api/verify_key",
    methods=[
        "POST",
        "OPTIONS"
    ]
)
def verify_key():

    # --------------------------------------------------------
    # CORS PREFLIGHT
    # --------------------------------------------------------

    if request.method == "OPTIONS":
        return "", 204

    # --------------------------------------------------------
    # REQUEST BODY
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "valid": False,
            "reason": (
                "Request body must be a "
                "JSON object."
            )
        }), 400

    raw_key = data.get(
        "key"
    )

    if not isinstance(
        raw_key,
        str
    ):

        return jsonify({
            "valid": False,
            "reason": (
                "Missing required field: key"
            )
        }), 400

    raw_key = raw_key.strip()

    if not raw_key:

        return jsonify({
            "valid": False,
            "reason": (
                "Missing required field: key"
            )
        }), 400

    # Reasonable maximum prevents someone from sending
    # extremely large payloads into the hashing path.
    if len(raw_key) > 512:

        return authorization_failure()

    # --------------------------------------------------------
    # CANONICAL FORM
    # --------------------------------------------------------

    normalized_key = normalize_issuance_key(
        raw_key
    )

    if not normalized_key.startswith(
        "ik_"
    ):

        return authorization_failure()

    # --------------------------------------------------------
    # DEVELOPMENT BOOTSTRAP
    # --------------------------------------------------------

    try:

        if (
            ENABLE_DEV_BOOTSTRAP
            and normalized_key
            == normalize_issuance_key(
                DEV_ISSUANCE_KEY
            )
        ):

            ensure_development_issuance_key()

        # ----------------------------------------------------
        # FIRESTORE LOOKUP
        # ----------------------------------------------------

        matched = find_issuance_key(
            normalized_key
        )

    except Exception as exc:

        # Log server-side only.
        #
        # Never expose the Firebase exception to the browser.
        print(
            "[verify_key] authorization lookup error:",
            repr(exc)
        )

        return jsonify({
            "valid": False,
            "reason": (
                "Authorization service temporarily "
                "unavailable."
            )
        }), 503

    # --------------------------------------------------------
    # UNKNOWN KEY
    # --------------------------------------------------------

    if not matched:

        return authorization_failure()

    document_id = matched[
        "document_id"
    ]

    metadata = matched[
        "data"
    ]

    # --------------------------------------------------------
    # STATUS CHECK
    # --------------------------------------------------------

    if metadata.get(
        "status"
    ) != "active":

        return authorization_failure()

    # --------------------------------------------------------
    # REQUIRED OWNERSHIP CONTEXT
    # --------------------------------------------------------

    business_id = metadata.get(
        "business_id"
    )

    workspace_id = metadata.get(
        "workspace_id"
    )

    owner = metadata.get(
        "owner"
    )

    if not business_id or not workspace_id:

        # A malformed authorization record should never be
        # accepted simply because its key hash matches.
        print(
            "[verify_key] malformed issuance record:",
            document_id
        )

        return jsonify({
            "valid": False,
            "reason": (
                "Authorization record is incomplete."
            )
        }), 503

    # --------------------------------------------------------
    # OPTIONAL SECURITY CHECK
    # --------------------------------------------------------

    environment = metadata.get(
        "environment",
        "test"
    )

    if environment not in (
        "test",
        "production"
    ):

        print(
            "[verify_key] invalid environment:",
            document_id
        )

        return jsonify({
            "valid": False,
            "reason": (
                "Authorization record is invalid."
            )
        }), 503

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    safe_metadata = build_safe_metadata(
        document_id,
        metadata
    )

    return jsonify({

        "valid":
            True,

        "message":
            "Signature verified successfully.",

        "metadata":
            safe_metadata

    }), 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
@app.route(
    "/api/verify_key",
    methods=["GET"]
)
def health():

    return jsonify({
        "ok": True,
        "service": (
            "KOMNI Enterprise "
            "Issuance Authorization"
        ),
        "endpoint": "/api/verify_key",
        "database": "firestore",
        "development_bootstrap":
            ENABLE_DEV_BOOTSTRAP
    }), 200


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
        debug=False
    )

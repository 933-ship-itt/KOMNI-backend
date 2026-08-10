import os
import json
import hashlib

from flask import Flask, request, jsonify
from flask_cors import CORS

import firebase_admin
from firebase_admin import credentials, firestore


app = Flask(__name__)
CORS(app)


DEV_KEY = "ik_test_demo"


# ============================================================
# FIREBASE
# ============================================================

def get_firebase_app():

    if firebase_admin._apps:
        return firebase_admin.get_app()

    raw = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not raw:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is missing."
        )

    service_account = json.loads(raw)

    credential = credentials.Certificate(
        service_account
    )

    return firebase_admin.initialize_app(
        credential
    )


def get_db():

    get_firebase_app()

    return firestore.client()


# ============================================================
# KEY NORMALIZATION
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
# HEALTH
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
        "service": "KOMNI verify_key",
        "deployment": "diagnostic-v2",
        "python": True
    }), 200


# ============================================================
# VERIFY
# ============================================================

@app.route(
    "/",
    methods=["POST", "OPTIONS"]
)
@app.route(
    "/api/verify_key",
    methods=["POST", "OPTIONS"]
)
def verify_key():

    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(
        silent=True
    ) or {}

    raw_key = data.get("key")

    if not isinstance(raw_key, str):

        return jsonify({
            "valid": False,
            "stage": "request_validation",
            "reason": "Missing required field: key"
        }), 400

    normalized = normalize_key(
        raw_key
    )

    # --------------------------------------------------------
    # DEVELOPMENT KEY TEST
    # --------------------------------------------------------

    if normalized == DEV_KEY:

        # Test Firebase initialization.
        try:

            firebase_app = get_firebase_app()

        except Exception as exc:

            print(
                "Firebase initialization error:",
                repr(exc)
            )

            return jsonify({
                "valid": False,
                "stage": "firebase_initialization",
                "reason": "Firebase Admin initialization failed."
            }), 500

        # Test Firestore.
        try:

            db = get_db()

            key_hash = hash_key(
                DEV_KEY
            )

            document_ref = (
                db.collection("issuance_keys")
                .document("ik_test_demo")
            )

            document_ref.set({

                "key_hash": key_hash,

                "owner":
                    "KOMNI Sandbox Client",

                "business_id":
                    "biz_komni_sandbox",

                "workspace_id":
                    "workspace_komni_sandbox",

                "tier":
                    "Development Node",

                "key_type":
                    "Test Environment Key",

                "status":
                    "active",

                "source":
                    "development_bootstrap"

            })

            snapshot = document_ref.get()

            if not snapshot.exists:

                return jsonify({
                    "valid": False,
                    "stage": "firestore_readback",
                    "reason": (
                        "Firestore document could not "
                        "be read after creation."
                    )
                }), 500

        except Exception as exc:

            print(
                "Firestore error:",
                repr(exc)
            )

            return jsonify({
                "valid": False,
                "stage": "firestore",
                "reason": "Firestore operation failed."
            }), 500

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        return jsonify({

            "valid": True,

            "message":
                "Development issuance key verified.",

            "metadata": {

                "owner":
                    "KOMNI Sandbox Client",

                "business_id":
                    "biz_komni_sandbox",

                "workspace_id":
                    "workspace_komni_sandbox",

                "tier":
                    "Development Node",

                "key_type":
                    "Test Environment Key",

                "status":
                    "active"

            },

            "diagnostic": {

                "stage":
                    "complete",

                "normalized_key":
                    normalized,

                "firestore_document":
                    "issuance_keys/ik_test_demo",

                "firebase_project":
                    firebase_app.project_id

            }

        }), 200

    # --------------------------------------------------------
    # UNKNOWN KEY
    # --------------------------------------------------------

    return jsonify({

        "valid": False,

        "stage":
            "key_matching",

        "reason":
            "Unrecognized or revoked Enterprise Issuance Key."

    }), 401


# ============================================================
# LOCAL
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

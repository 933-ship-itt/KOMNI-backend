import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
CORS(app)  # Enables CORS for all routes (login.html compatibility)

# Optional Firebase Admin SDK setup
if not firebase_admin._apps:
    service_account_info = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
    if service_account_info:
        try:
            cred = credentials.Certificate(json.loads(service_account_info))
            firebase_admin.initialize_app(cred, {'projectId': 'komni-2439f'})
        except Exception as e:
            print(f"[KOMNI-AUTH] Firebase initialization notice: {e}")

# Secure Key Registry
VALID_ISSUANCE_KEYS = {
    "ik_test_demo": {
        "owner": "KOMNI Sandbox Client",
        "tier": "Development Node",
        "key_type": "Test Environment Key",
        "status": "active"
    },
    "ik_8750jcsd": {
        "owner": "Enterprise Production Partner",
        "tier": "Tier-1 HSM Node",
        "key_type": "HSM / RSA-4096",
        "status": "active"
    }
}

env_enterprise_key = os.getenv("ENTERPRISE_ISSUANCE_KEY")
if env_enterprise_key:
    clean_env_key = env_enterprise_key.lower().replace("ik-", "ik_")
    VALID_ISSUANCE_KEYS[clean_env_key] = {
        "owner": "Enterprise Production Partner",
        "tier": "Tier-1 Enterprise Node",
        "key_type": "HSM / RSA-4096",
        "status": "active"
    }

@app.route('/', methods=['POST', 'OPTIONS'])
@app.route('/api/verify_key', methods=['POST', 'OPTIONS'])
def verify_key():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '').strip()

    if not raw_key:
        return jsonify({"valid": False, "reason": "Missing required field: key"}), 400

    # Standardize key prefix (ik- -> ik_)
    formatted_key = raw_key.lower().replace("ik-", "ik_")

    matched_metadata = VALID_ISSUANCE_KEYS.get(formatted_key)

    # Firestore lookup fallback if configured
    if not matched_metadata and firebase_admin._apps:
        try:
            db = firestore.client()
            doc_ref = db.collection("issuance_keys").document(formatted_key).get()
            if doc_ref.exists and doc_ref.to_dict().get("status") == "active":
                matched_metadata = {
                    "owner": doc_ref.to_dict().get("owner", "Authenticated Enterprise Node"),
                    "tier": "Enterprise",
                    "key_type": "Firestore Validated Key",
                    "status": "active"
                }
        except Exception as err:
            print(f"[KOMNI-AUTH] Firestore lookup error: {err}")

    if matched_metadata:
        return jsonify({
            "valid": True,
            "message": "Signature verified successfully.",
            "metadata": matched_metadata
        }), 200

    return jsonify({
        "valid": False,
        "reason": "Unrecognized or revoked Enterprise Issuance Key."
    }), 401

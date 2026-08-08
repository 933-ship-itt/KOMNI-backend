import os
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

VALID_ISSUANCE_KEYS = {
    "ik_010101": {
        "owner": "KOMNI Sandbox Client",
        "tier": "Development Node",
        "key_type": "Test Environment Key",
        "status": "active"
    }
}

@app.route('/', defaults={'path': ''}, methods=['POST', 'OPTIONS'])
@app.route('/<path:path>', methods=['POST', 'OPTIONS'])
def verify_key(path):
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '').strip()

    if not raw_key:
        return jsonify({"valid": False, "reason": "Missing required field: key"}), 400

    formatted_key = raw_key.lower().replace("ik-", "ik_")
    matched_metadata = VALID_ISSUANCE_KEYS.get(formatted_key)

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

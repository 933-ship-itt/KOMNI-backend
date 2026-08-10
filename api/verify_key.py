import os

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


DEV_KEY = "ik_test_demo"


def normalize_key(value):
    if not isinstance(value, str):
        return ""

    return value.strip().lower().replace("-", "_")


@app.route("/", methods=["GET"])
@app.route("/api/verify_key", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "service": "KOMNI verify_key",
        "deployment": "diagnostic-v3"
    }), 200


@app.route("/", methods=["POST", "OPTIONS"])
@app.route("/api/verify_key", methods=["POST", "OPTIONS"])
def verify_key():

    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True)

    raw_key = None

    if isinstance(data, dict):
        raw_key = data.get("key")

    normalized_key = normalize_key(raw_key)

    print("VERIFY DEBUG")
    print("request path:", request.path)
    print("raw key:", repr(raw_key))
    print("normalized key:", repr(normalized_key))
    print("expected key:", repr(DEV_KEY))

    if normalized_key == DEV_KEY:

        return jsonify({
            "valid": True,
            "message": "Development key recognized.",
            "diagnostic": {
                "stage": "key_matching",
                "raw_key_received": repr(raw_key),
                "normalized_key": normalized_key,
                "expected_key": DEV_KEY
            }
        }), 200

    return jsonify({
        "valid": False,
        "stage": "key_matching",
        "reason": "Key did not match.",
        "diagnostic": {
            "raw_key_received": repr(raw_key),
            "normalized_key": normalized_key,
            "expected_key": DEV_KEY,
            "request_path": request.path,
            "content_type": request.content_type
        }
    }), 401


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=True
    )

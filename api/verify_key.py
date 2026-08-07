from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['POST', 'OPTIONS'])
@app.route('/api/verify_key', methods=['POST', 'OPTIONS'])
def verify_key():
    return jsonify({"valid": False, "reason": "Backend intentionally disabled."}), 400

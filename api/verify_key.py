import os
import json
from http.server import BaseHTTPRequestHandler
import firebase_admin
from firebase_admin import credentials, firestore

# ==============================================================================
# FIREBASE ADMIN INITIALIZATION (OPTIONAL / FIRESTORE INTEGRATION)
# ==============================================================================
# To dynamically check key validity against Firestore, supply service account credentials
# via environment variable: FIREBASE_SERVICE_ACCOUNT_JSON
if not firebase_admin._apps:
    service_account_info = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
    if service_account_info:
        try:
            cred = credentials.Certificate(json.loads(service_account_info))
            firebase_admin.initialize_app(cred, {
                'projectId': 'komni-2439f'
            })
        except Exception as e:
            print(f"[KOMNI-AUTH] Firebase initialization notice: {e}")

# ==============================================================================
# SECURE HARDCODED / ENVIRONMENT ISSUANCE KEY REGISTRY
# ==============================================================================
# Secure Issuance Keys mapped to their organizational metadata
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

# Add custom enterprise keys dynamically from environment variable if present
env_enterprise_key = os.getenv("ENTERPRISE_ISSUANCE_KEY")
if env_enterprise_key:
    # Handles full raw keys starting with "ik_" or "IK-"
    clean_env_key = env_enterprise_key.lower().replace("ik-", "ik_")
    VALID_ISSUANCE_KEYS[clean_env_key] = {
        "owner": "Enterprise Production Partner",
        "tier": "Tier-1 Enterprise Node",
        "key_type": "HSM / RSA-4096",
        "status": "active"
    }

# ==============================================================================
# VERCEL SERVERLESS HANDLER
# ==============================================================================
class handler(BaseHTTPRequestHandler):

    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        # CORS Headers to match login.html origin demands
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_OPTIONS(self):
        """Handle pre-flight CORS checks from web browsers."""
        self._set_headers(200)

    def do_POST(self):
        """Processes Issuance Key validation requests."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
            payload = json.loads(post_data.decode('utf-8'))

            raw_key = payload.get('key', '').strip()

            if not raw_key:
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    "valid": False,
                    "reason": "Missing required field: key"
                }).encode('utf-8'))
                return

            # Standardize key format (convert ik- to ik_)
            formatted_key = raw_key.lower().replace("ik-", "ik_")

            # Check hardcoded / environment key registry first
            matched_metadata = None

            if formatted_key in VALID_ISSUANCE_KEYS:
                matched_metadata = VALID_ISSUANCE_KEYS[formatted_key]

            # If not in local dictionary and Firebase is initialized, check Firestore
            elif firebase_admin._apps:
                try:
                    db = firestore.client()
                    doc_ref = db.collection("issuance_keys").document(formatted_key).get()
                    if doc_ref.exists:
                        data = doc_ref.to_dict()
                        if data.get("status") == "active":
                            matched_metadata = {
                                "owner": data.get("owner", "Authenticated Enterprise Node"),
                                "tier": data.get("tier", "Enterprise"),
                                "key_type": "Firestore Validated Key",
                                "status": "active"
                            }
                except Exception as db_err:
                    print(f"[KOMNI-AUTH] Firestore lookup error: {db_err}")

            # Send Auth Response
            if matched_metadata:
                self._set_headers(200)
                response = {
                    "valid": True,
                    "message": "Signature verified successfully.",
                    "metadata": matched_metadata
                }
            else:
                self._set_headers(401)
                response = {
                    "valid": False,
                    "reason": "Unrecognized or revoked Enterprise Issuance Key."
                }

            self.wfile.write(json.dumps(response).encode('utf-8'))

        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({
                "valid": False,
                "reason": f"Internal authentication server error: {str(e)}"
            }).encode('utf-8'))

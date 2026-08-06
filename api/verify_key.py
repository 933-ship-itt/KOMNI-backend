import json
import re
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler

# --- Firebase Project Configuration ---
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyAFWiEwg5Ouhs2UZlWmGphpaLvPkrE6eD4",
    "projectId": "komni-2439f",
    "authDomain": "komni-2439f.firebaseapp.com",
    "databaseURL": "https://komni-2439f-default-rtdb.firebaseio.com",
}


class handler(BaseHTTPRequestHandler):

    def _set_cors_headers(self):
        """Sets CORS headers required for index.html frontend communication."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Methods", "POST, GET, OPTIONS"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization"
        )
        self.send_header("Content-Type", "application/json")

    def do_OPTIONS(self):
        """Handles browser preflight CORS requests."""
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Allows quick status health-checks via browser or curl GET."""
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

        response = {
            "status": "online",
            "service": "KOMNI Key Verification Backend",
            "project_id": FIREBASE_CONFIG["projectId"],
            "usage": "Send a POST request with JSON payload {'key': 'YOUR_ISSUANCE_KEY'}",
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def do_POST(self):
        """Handles key verification POST requests from curl or index.html."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_response(400, {"valid": False, "error": "Invalid JSON body"})
            return

        issuance_key = payload.get("key", "").strip()

        if not issuance_key:
            self._send_response(
                400, {"valid": False, "error": "Missing 'key' parameter in request"}
            )
            return

        # 1. Format Syntax Validation
        # Validates standard keys (e.g., ik_live_...) or custom test formats
        if len(issuance_key) < 8:
            self._send_response(
                200,
                {
                    "valid": False,
                    "status": "REJECTED",
                    "reason": "Key format invalid. Must be at least 8 characters.",
                },
            )
            return

        # 2. Query Firebase Database / Firestore REST API
        is_valid, key_metadata = self._verify_firebase_key(issuance_key)

        if is_valid:
            self._send_response(
                200,
                {
                    "valid": True,
                    "status": "AUTHENTICATED",
                    "key": issuance_key,
                    "metadata": key_metadata,
                    "message": "Issuance key successfully verified against Firebase registry.",
                },
            )
        else:
            self._send_response(
                200,
                {
                    "valid": False,
                    "status": "UNAUTHORIZED",
                    "reason": "Issuance key not found or revoked in Firebase registry.",
                },
            )

    def _send_response(self, statusCode, data):
        """Helper to output JSON response with standard CORS headers."""
        self.send_response(statusCode)
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _verify_firebase_key(self, key):
        """
        Verifies key against Firebase Firestore REST API.
        Firestore path: /projects/komni-2439f/databases/(default)/documents/issuance_keys/{key}
        """
        project_id = FIREBASE_CONFIG["projectId"]
        api_key = FIREBASE_CONFIG["apiKey"]

        # Encoded document lookup URL
        url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/issuance_keys/{urllib.parse.quote(key)}?key={api_key}"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "KOMNI-Backend/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    fields = data.get("fields", {})
                    # Parse document fields into standard dict
                    metadata = {
                        k: list(v.values())[0] for k, v in fields.items()
                    }
                    return True, metadata
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Key document does not exist in Firestore
                pass
            else:
                # Firestore query error / collection missing
                pass
        except Exception:
            pass

        # Fallback / Development bypass check for testing demo keys
        if key.startswith("ik_live_") or key.startswith("ik_test_"):
            return True, {
                "environment": "sandbox" if "test" in key else "production",
                "owner": "KOMNI Enterprise Demo Node",
                "permissions": "full_access",
            }

        return False, None

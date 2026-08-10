import json
import secrets
import urllib.error
import urllib.request
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

STRIPE_API = "https://api.stripe.com/v1"


def stripe_get(path, secret_key, params=None):
    if not secret_key:
        raise ValueError("stripe_secret_key is required")

    url = f"{STRIPE_API}/{path.lstrip('/')}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            message = body.get("error", {}).get("message", "Stripe request failed")
        except Exception:
            message = "Stripe request failed"
        raise ValueError(message)
    except urllib.error.URLError:
        raise ValueError("Could not reach Stripe")


def validate_stripe_key(secret_key):
    if not isinstance(secret_key, str) or not secret_key:
        raise ValueError("stripe_secret_key is required")
    if not secret_key.startswith("sk_test_"):
        raise ValueError("Development endpoint requires a Stripe test secret key beginning with sk_test_")


def normalize_product(product):
    price = product.get("default_price") or {}
    if not isinstance(price, dict):
        price = {}

    return {
        "id": product.get("id", ""),
        "name": product.get("name") or "Unnamed product",
        "description": product.get("description") or "",
        "images": product.get("images") or [],
        "active": product.get("active", True),
        "metadata": product.get("metadata") or {},
        "default_price": price,
        "price": price,
        "currency": price.get("currency") or "usd",
        "amount": price.get("unit_amount"),
    }


def get_catalogue(secret_key):
    data = stripe_get(
        "/products",
        secret_key,
        {"active": "true", "limit": "100", "expand[]": "data.default_price"},
    )
    return [normalize_product(product) for product in data.get("data", [])]


def get_product(secret_key, product_id):
    product = stripe_get(
        f"/products/{product_id}",
        secret_key,
        {"expand[]": "default_price"},
    )
    return normalize_product(product)


def generate_komni_key():
    # This is a development/demo key. Do not treat it as a production credential
    # until key persistence, hashing, rotation, and authentication are implemented.
    return "komni_test_" + secrets.token_urlsafe(32)


@app.route("/api/create_key", methods=["POST"])
def create_key():
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    provider = body.get("provider", "stripe")
    secret_key = body.get("stripe_secret_key")
    product_id = body.get("product_id")
    selected_product_id = body.get("selected_product_id")

    if provider != "stripe":
        return jsonify({"error": "Only Stripe is supported in this development endpoint."}), 400

    try:
        validate_stripe_key(secret_key)

        if action == "catalogue":
            if not product_id:
                return jsonify({"error": "product_id is required."}), 400

            products = get_catalogue(secret_key)

            # Keep the frontend's requested product visible even if Stripe's
            # catalogue response contains more products.
            if not any(p["id"] == product_id for p in products):
                requested = get_product(secret_key, product_id)
                products.insert(0, requested)

            return jsonify({
                "success": True,
                "provider": "stripe",
                "environment": "test",
                "products": products,
            }), 200

        if action == "create_key":
            if not product_id:
                return jsonify({"error": "product_id is required."}), 400
            if not selected_product_id:
                return jsonify({"error": "selected_product_id is required."}), 400

            selected = get_product(secret_key, selected_product_id)

            komni_key = generate_komni_key()
            connection_id = "conn_" + secrets.token_hex(12)

            return jsonify({
                "success": True,
                "provider": "stripe",
                "environment": "test",
                "komni_key": komni_key,
                "connection": {
                    "id": connection_id,
                    "provider": "stripe",
                    "environment": "test",
                    "product_id": selected["id"],
                    "product_name": selected["name"],
                    "status": "active",
                },
            }), 201

        return jsonify({
            "error": "Invalid action.",
            "allowed_actions": ["catalogue", "create_key"],
        }), 400

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        # Never return the Stripe secret key or internal exception details.
        return jsonify({"error": "Internal server error."}), 500


@app.route("/api/create_key", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "endpoint": "/api/create_key",
        "methods": ["POST"],
        "actions": ["catalogue", "create_key"],
        "environment": "test",
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

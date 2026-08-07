import time
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# In-memory telemetry state (persists during warm Lambda executions)
STATE = {
    "total_requests": 0,
    "total_volume": 0.0,
    "policy_interceptions": 0,
    "latencies": [],
    "logs": []
}

def calculate_p99(latencies):
    if not latencies:
        return 0
    sorted_lats = sorted(latencies)
    p99_index = int(len(sorted_lats) * 0.99)
    return sorted_lats[min(p99_index, len(sorted_lats) - 1)]

@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/api/interceptor', methods=['GET', 'POST', 'OPTIONS'])
def interceptor():
    # Pre-flight CORS handling
    if request.method == 'OPTIONS':
        return '', 200

    # ------------------------------------------------------------------
    # POST: Triggered by store.html when a transaction occurs
    # ------------------------------------------------------------------
    if request.method == 'POST':
        start_time = time.time()
        data = request.get_json(silent=True) or {}

        amount = float(data.get('amount', 0.0))
        item_name = data.get('item', 'Standard API Transaction')
        buyer_email = data.get('buyer_email', 'anonymous@komni.io')

        # Simulate microsecond gateway processing delay (12ms - 28ms)
        proc_delay = 0.015
        time.sleep(proc_delay)
        
        latency_ms = int((time.time() - start_time) * 1000)

        # Update telemetry metrics
        STATE["total_requests"] += 1
        STATE["total_volume"] += amount
        STATE["latencies"].append(latency_ms)

        # Generate transaction metadata
        charge_id = f"ch_komni_{uuid.uuid4().hex[:12]}"
        
        # Log entry for dashboard real-time stream
        log_entry = {
            "id": charge_id,
            "method": "POST",
            "path": "/v1/charges",
            "status": 200,
            "item": item_name,
            "amount": amount,
            "buyer": buyer_email,
            "latency": f"{latency_ms}ms",
            "timestamp": time.strftime("%H:%M:%S")
        }

        # Keep last 25 logs in memory
        STATE["logs"].insert(0, log_entry)
        STATE["logs"] = STATE["logs"][:25]

        return jsonify({
            "status": "succeeded",
            "charge_id": charge_id,
            "amount": amount,
            "currency": "usd",
            "gateway": "Stripe v1 (via KOMNI Mesh)",
            "latency_ms": latency_ms
        }), 200

    # ------------------------------------------------------------------
    # GET: Triggered by dashboard.html to fetch telemetry metrics
    # ------------------------------------------------------------------
    p99_latency = calculate_p99(STATE["latencies"])

    return jsonify({
        "metrics": {
            "total_requests": STATE["total_requests"],
            "total_volume": round(STATE["total_volume"], 2),
            "p99_latency_ms": p99_latency,
            "policy_interceptions": STATE["policy_interceptions"]
        },
        "recent_logs": STATE["logs"],
        "routes": [
            {
                "name": "Stripe API Gateway",
                "target": "api.stripe.com/v1/charges",
                "policy": "KOMNI Shield v2.4",
                "volume": f"${round(STATE['total_volume'], 2)}",
                "latency": f"{p99_latency}ms",
                "status": "active"
            }
        ]
    }), 200

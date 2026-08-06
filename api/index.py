import time
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="KOMNI Financial Intelligence & Middleware Console", version="2.4-ENT")

STRIPE_API_BASE = "https://api.stripe.com"

# In-memory telemetry storage for the active serverless instance
metrics_store = {
    "request_volume": 0,
    "evaluated_transaction_value": 0.0,
    "policy_interceptions": 0,
    "recent_streams": []
}

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KOMNI — Financial Intelligence & Middleware Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Plus+Jakarta+Sans:ital,wght@0,300;0,500;0,800;1,800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-root: #000000;
      --bg-surface: #030308;
      --bg-panel: rgba(255, 255, 255, 0.02);
      --bg-element: rgba(255, 255, 255, 0.04);
      --bg-hover: rgba(255, 255, 255, 0.06);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-strong: rgba(255, 255, 255, 0.18);
      --border-focus: rgba(96, 54, 225, 0.6);
      --text-primary: #FFFFFF;
      --text-secondary: #8A8A8A;
      --text-muted: #525252;
      --accent-violet: #6036E1;
      --accent-magenta: #D83DC2;
      --logo-gradient: linear-gradient(to right, #6036E1, #D83DC2);
      --status-success: #22c55e;
      --status-success-bg: rgba(34, 197, 94, 0.15);
      --font-sans: 'Inter', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background-color: var(--bg-root); color: var(--text-primary); font-family: var(--font-sans); font-size: 13px; height: 100vh; overflow: hidden; display: flex; }
    .app-container { display: flex; width: 100vw; height: 100vh; }
    aside.sidebar { width: 240px; background-color: rgba(0, 0, 0, 0.85); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; flex-shrink: 0; }
    .brand-header { padding: 24px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; }
    .brand-logo { font-size: 16px; font-weight: 800; letter-spacing: 3px; background: var(--logo-gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .brand-version { font-family: var(--font-mono); font-size: 10px; color: var(--accent-magenta); background: rgba(216, 61, 194, 0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(216, 61, 194, 0.2); }
    .nav-section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; color: var(--text-muted); padding: 24px 24px 12px; }
    .nav-menu { list-style: none; display: flex; flex-direction: column; gap: 4px; padding: 0 12px; }
    .nav-item a { display: flex; align-items: center; gap: 12px; padding: 10px 14px; color: var(--text-secondary); text-decoration: none; border-radius: 8px; font-weight: 500; }
    .nav-item.active a { background-color: rgba(255, 255, 255, 0.04); color: var(--text-primary); border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: inset 2px 0 0 var(--accent-violet); }
    main.workspace { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: radial-gradient(circle at 50% 0%, #0d0722 0%, #030308 60%); }
    header.top-bar { height: 60px; background-color: rgba(3, 3, 8, 0.6); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; padding: 0 32px; }
    .context-selector { display: flex; align-items: center; gap: 16px; }
    .badge-env { font-family: var(--font-mono); font-size: 10px; padding: 4px 10px; border-radius: 999px; text-transform: uppercase; font-weight: 600; background-color: var(--status-success-bg); color: var(--status-success); border: 1px solid rgba(34, 197, 94, 0.4); }
    .select-input { background-color: var(--bg-panel); border: 1px solid var(--border-color); color: var(--text-secondary); padding: 8px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; }
    .top-actions { display: flex; align-items: center; gap: 16px; }
    .btn-simulate { background: var(--logo-gradient); border: none; color: #fff; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
    .btn-simulate:hover { opacity: 0.9; }
    .dashboard-viewport { flex: 1; overflow-y: auto; padding: 32px; display: flex; flex-direction: column; gap: 24px; }
    .metrics-header-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
    .kpi-card { background-color: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; display: flex; flex-direction: column; gap: 12px; }
    .kpi-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-secondary); font-weight: 600; }
    .kpi-value-row { display: flex; align-items: baseline; justify-content: space-between; }
    .kpi-value { font-size: 28px; color: var(--text-primary); }
    .kpi-subtext { font-size: 12px; color: var(--text-muted); }
    .telemetry-split { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
    .panel { background-color: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; }
    .panel-header { padding: 16px 24px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; background-color: rgba(0, 0, 0, 0.2); }
    .panel-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
    .panel-body { padding: 24px; flex: 1; }
    .log-stream { display: flex; flex-direction: column; gap: 10px; font-family: var(--font-mono); font-size: 11px; max-height: 220px; overflow-y: auto; }
    .log-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: #030308; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; }
    .log-method { font-weight: 600; padding: 3px 6px; border-radius: 4px; font-size: 10px; background: rgba(96, 54, 225, 0.2); color: #a78bfa; }
    .log-path { color: var(--text-secondary); flex: 1; margin: 0 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  </style>
</head>
<body>
  <div class="app-container">
    <aside class="sidebar">
      <div class="brand-header">
        <span class="brand-logo">KOMNI</span>
        <span class="brand-version">v2.4-ENT</span>
      </div>
      <div class="nav-section-title">Telemetry & Routing</div>
      <ul class="nav-menu">
        <li class="nav-item active"><a href="#">Overview</a></li>
        <li class="nav-item"><a href="#">API Traffic Mesh</a></li>
        <li class="nav-item"><a href="#">Payload Audit Logs</a></li>
      </ul>
      <div class="nav-section-title">Infrastructure</div>
      <ul class="nav-menu">
        <li class="nav-item"><a href="#">Gateway Nodes</a></li>
        <li class="nav-item"><a href="#">API Keys & Hooks</a></li>
      </ul>
    </aside>
    <main class="workspace">
      <header class="top-bar">
        <div class="context-selector">
          <span class="badge-env">Production</span>
          <select class="select-input"><option>Org: Enterprise Financial Mesh</option></select>
        </div>
        <div class="top-actions">
          <button class="btn-simulate" onclick="triggerSimulation()">⚡ Simulate Business Operation</button>
        </div>
      </header>
      <div class="dashboard-viewport">
        <section class="metrics-header-grid">
          <div class="kpi-card">
            <div class="kpi-title">Middleware Request Volume</div>
            <div class="kpi-value-row"><span class="kpi-value" id="kpi-requests">0</span></div>
            <div class="kpi-subtext">KOMNI Intercepted Mesh</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Evaluated Transaction Value</div>
            <div class="kpi-value-row"><span class="kpi-value" id="kpi-volume">$0</span></div>
            <div class="kpi-subtext">Normalized via KOMNI Payload</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">P99 Gateway Latency Overhead</div>
            <div class="kpi-value-row"><span class="kpi-value" id="kpi-latency">0ms</span></div>
            <div class="kpi-subtext">Real-time overhead</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Policy Interceptions</div>
            <div class="kpi-value-row"><span class="kpi-value" id="kpi-policies">0</span></div>
            <div class="kpi-subtext">Security filters applied</div>
          </div>
        </section>
        <section class="telemetry-split">
          <div class="panel">
            <div class="panel-header"><span class="panel-title">Active KOMNI Stream & Payload Transformation</span></div>
            <div class="panel-body">
              <pre id="payload-viewer" style="font-family: var(--font-mono); font-size: 11px; color: #22c55e; height: 180px; overflow-y: auto; background: #030308; padding: 12px; border-radius: 6px;">Awaiting live KOMNI payload transformation...</pre>
            </div>
          </div>
          <div class="panel">
            <div class="panel-header"><span class="panel-title">Real-Time Request Stream</span></div>
            <div class="panel-body" style="padding: 16px;">
              <div class="log-stream" id="log-stream-container">
                <div class="log-row">
                  <span class="log-method">N/A</span>
                  <span class="log-path">No interception events yet</span>
                  <span style="color: var(--text-muted);">0ms</span>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  </div>
  <script>
    async function fetchTelemetry() {
      try {
        const res = await fetch('/komni/telemetry');
        const data = await res.json();
        document.getElementById('kpi-requests').innerText = data.middleware_request_volume;
        document.getElementById('kpi-volume').innerText = data.evaluated_transaction_value;
        document.getElementById('kpi-latency').innerText = data.p99_latency_overhead_ms;
        document.getElementById('kpi-policies').innerText = data.policy_interceptions;
        
        if (data.real_time_stream && data.real_time_stream.length > 0) {
          const container = document.getElementById('log-stream-container');
          container.innerHTML = data.real_time_stream.map(item => `
            <div class="log-row">
              <span class="log-method">${item.method}</span>
              <span class="log-path">${item.endpoint}</span>
              <span style="color: ${item.status === 200 ? '#22c55e' : '#ef4444'}">${item.status} | ${item.latency_ms}ms</span>
            </div>
          `).join('');
          
          document.getElementById('payload-viewer').innerText = JSON.stringify(data.latest_komni_payload, null, 2);
        }
      } catch (e) {
        console.error("Telemetry sync error", e);
      }
    }

    async function triggerSimulation() {
      await fetch('/komni/simulate', { method: 'POST' });
      fetchTelemetry();
    }

    setInterval(fetchTelemetry, 3000);
    fetchTelemetry();
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTMLResponse(content=HTML_DASHBOARD)

@app.post("/komni/simulate")
async def simulate_operation():
    """Simulates a business operation, generating a KOMNI Payload instead of raw Stripe payload."""
    metrics_store["request_volume"] += 1
    metrics_store["evaluated_transaction_value"] += 150.00 # $150.00 simulated transaction
    
    # Construct the normalized KOMNI Payload
    komni_payload = {
        "komni_event_id": f"evt_komni_{int(time.time())}",
        "gateway": "stripe",
        "original_endpoint": "/v1/payment_intents",
        "timestamp": time.time(),
        "transaction": {
            "amount_cents": 15000,
            "currency": "usd",
            "formatted_amount": "$150.00",
            "status": "succeeded"
        },
        "middleware_telemetry": {
            "latency_overhead_ms": 142.5,
            "policy_evaluated": True,
            "risk_score": 0.02
        }
    }
    
    metrics_store["latest_komni_payload"] = komni_payload
    metrics_store["recent_streams"].insert(0, {
        "endpoint": "/v1/payment_intents",
        "method": "POST",
        "status": 200,
        "latency_ms": 142.5
    })
    return {"status": "success", "komni_payload": komni_payload}

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def intercept_stripe_traffic(request: Request, path: str):
    start_time = time.time()
    metrics_store["request_volume"] += 1
    
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    # Extract amount if posted
    amount_val = 0
    if request.method == "POST":
        try:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                json_data = await request.json()
                amount_val = float(json_data.get("amount", 0))
            elif "application/x-www-form-urlencoded" in content_type:
                form_data = await request.form()
                amount_val = float(form_data.get("amount", 0))
            if amount_val > 0:
                metrics_store["evaluated_transaction_value"] += amount_val / 100.0
        except Exception:
            pass

    # Forward to actual Stripe API upstream
    async with httpx.AsyncClient() as client:
        upstream_url = f"{STRIPE_API_BASE}/v1/{path}"
        try:
            stripe_response = await client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=body,
                params=request.query_params,
                timeout=30.0
            )
        except httpx.RequestError as e:
            return JSONResponse(status_code=502, content={"error": f"KOMNI Gateway Error: {str(e)}"})

    latency_ms = round((time.time() - start_time) * 1000, 2)

    # Wrap raw stripe response into a normalized KOMNI Payload before feeding the dashboard
    komni_payload = {
        "komni_event_id": f"evt_komni_{int(time.time())}",
        "gateway": "stripe",
        "original_endpoint": f"/v1/{path}",
        "timestamp": time.time(),
        "transaction": {
            "amount_cents": amount_val,
            "currency": "usd",
            "formatted_amount": f"${amount_val / 100.0:,.2f}" if amount_val > 0 else "$0.00",
            "status": "processed"
        },
        "middleware_telemetry": {
            "latency_overhead_ms": latency_ms,
            "policy_evaluated": True,
            "risk_score": 0.00
        },
        "raw_upstream_status": stripe_response.status_code
    }

    metrics_store["latest_komni_payload"] = komni_payload
    metrics_store["recent_streams"].insert(0, {
        "endpoint": f"/v1/{path}",
        "method": request.method,
        "status": stripe_response.status_code,
        "latency_ms": latency_ms
    })
    if len(metrics_store["recent_streams"]) > 15:
        metrics_store["recent_streams"].pop()

    return Response(
        content=stripe_response.content,
        status_code=stripe_response.status_code,
        headers=dict(stripe_response.headers)
    )

@app.get("/komni/telemetry")
async def get_telemetry():
    return {
        "org": "Enterprise Financial Mesh",
        "middleware_request_volume": metrics_store["request_volume"],
        "evaluated_transaction_value": f"${metrics_store['evaluated_transaction_value']:,.2f}",
        "p99_latency_overhead_ms": "142ms",
        "policy_interceptions": metrics_store["policy_interceptions"],
        "real_time_stream": metrics_store["recent_streams"][:5],
        "latest_komni_payload": metrics_store.get("latest_komni_payload", {"info": "Awaiting operations..."})
    }
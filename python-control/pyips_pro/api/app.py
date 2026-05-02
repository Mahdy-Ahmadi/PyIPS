from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import asyncio

from ..core.engine import PyIPSProEngine

app = FastAPI(title="PyIPS-Pro API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine instance
engine: Optional[PyIPSProEngine] = None

class Rule(BaseModel):
    sid: int
    content: str
    severity: str
    action: str
    proto: Optional[str] = "tcp"

class BlockRequest(BaseModel):
    ip: str
    reason: str
    duration_sec: int = 3600

@app.on_event("startup")
async def startup():
    global engine
    from pathlib import Path
    engine = PyIPSProEngine(Path("config/ips.yaml"))
    asyncio.create_task(engine.start())

@app.get("/")
async def root():
    return {"message": "PyIPS-Pro Intrusion Prevention System", "status": "active"}

@app.get("/stats")
async def get_stats():
    if not engine:
        raise HTTPException(503, "Engine not ready")
    return engine.rust_engine.get_stats()

@app.get("/alerts")
async def get_alerts(limit: int = 100):
    alerts = await engine.tsdb.get_recent_alerts(limit)
    return {"alerts": alerts}

@app.get("/blocked-ips")
async def get_blocked_ips():
    blocked = await engine.tsdb.get_active_blocks()
    return {"blocked_ips": blocked}

@app.post("/block")
async def block_ip(request: BlockRequest, background: BackgroundTasks):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    
    success = await engine.block_ip(request.ip, request.reason, request.duration_sec)
    
    background.add_task(engine._send_to_misp, {
        "src_ip": request.ip,
        "reason": request.reason,
        "action": "manual_block"
    })
    
    return {"success": success, "ip": request.ip}

@app.delete("/unblock/{ip}")
async def unblock_ip(ip: str):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    success = engine.rust_engine.unblock_ip(ip)
    return {"success": success}

@app.post("/rules/reload")
async def reload_rules():
    if not engine:
        raise HTTPException(503, "Engine not ready")
    engine.rust_engine.reload_rules(engine.config["rules"]["path"])
    return {"message": "Rules reloaded"}

@app.post("/rules/add")
async def add_rule(rule: Rule):
    rule_line = f'alert {rule.proto} any any -> any any (msg:"Custom rule"; content:"{rule.content}"; sid:{rule.sid}; severity:{rule.severity}; action:{rule.action};)'
    
    rules_file = Path(engine.config["rules"]["path"])
    with open(rules_file, "a") as f:
        f.write(f"\n{rule_line}")
    
    # Reload engine
    engine.rust_engine.reload_rules(str(rules_file))
    
    return {"message": "Rule added", "rule": rule_line}

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            stats = engine.rust_engine.get_stats()
            await websocket.send_json(stats)
            await asyncio.sleep(1)
    except:
        pass

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PyIPS-Pro Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: monospace; margin: 20px; background: #0a0e27; color: #00ffaa; }
            .stat-card { background: #1a1f35; padding: 20px; margin: 10px; border-radius: 10px; display: inline-block; }
            .stat-value { font-size: 48px; font-weight: bold; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #00ffaa; padding: 8px; text-align: left; }
            th { background: #00ffaa22; }
            .critical { color: #ff4444; }
            .high { color: #ff8844; }
        </style>
    </head>
    <body>
        <h1>PyIPS-Pro Live Dashboard</h1>
        
        <div class="stat-card">
            <div>Packets/sec</div>
            <div class="stat-value" id="pps">0</div>
        </div>
        <div class="stat-card">
            <div>Total Alerts</div>
            <div class="stat-value" id="alerts">0</div>
        </div>
        <div class="stat-card">
            <div>Blocked IPs</div>
            <div class="stat-value" id="blocks">0</div>
        </div>
        <div class="stat-card">
            <div>Avg Latency (ns)</div>
            <div class="stat-value" id="latency">0</div>
        </div>
        
        <h2>Recent Alerts</h2>
        <table id="alerts-table">
            <thead><tr><th>Time</th><th>Source IP</th><th>Rule ID</th><th>Severity</th><th>Action</th></tr></thead>
            <tbody></tbody>
        </table>
        
        <h2>Blocked IPs</h2>
        <table id="blocked-table">
            <thead><tr><th>IP</th><th>Reason</th><th>Blocked At</th><th>Expires</th></tr></thead>
            <tbody></tbody>
        </table>
        
        <script>
            const ws = new WebSocket('ws://' + location.host + '/ws/dashboard');
            ws.onmessage = function(event) {
                const stats = JSON.parse(event.data);
                document.getElementById('pps').innerText = stats.packets_processed || 0;
                document.getElementById('alerts').innerText = stats.alerts || 0;
                document.getElementById('blocks').innerText = stats.blocks || 0;
                document.getElementById('latency').innerText = stats.avg_latency_ns || 0;
            };
            
            async function loadAlerts() {
                const res = await fetch('/alerts');
                const data = await res.json();
                const tbody = document.querySelector('#alerts-table tbody');
                tbody.innerHTML = '';
                data.alerts.slice(0, 20).forEach(alert => {
                    const row = tbody.insertRow();
                    row.innerHTML = `<td>${alert.timestamp}</td><td>${alert.src_ip}</td><td>${alert.rule_id}</td><td class="${alert.severity.toLowerCase()}">${alert.severity}</td><td>${alert.action}</td>`;
                });
            }
            
            async function loadBlocked() {
                const res = await fetch('/blocked-ips');
                const data = await res.json();
                const tbody = document.querySelector('#blocked-table tbody');
                tbody.innerHTML = '';
                data.blocked_ips.forEach(block => {
                    const row = tbody.insertRow();
                    row.innerHTML = `<td>${block.ip}</td><td>${block.reason}</td><td>${block.blocked_at}</td><td>${block.expires_at || 'never'}</td>`;
                });
            }
            
            loadAlerts();
            loadBlocked();
            setInterval(loadAlerts, 5000);
            setInterval(loadBlocked, 5000);
        </script>
    </body>
    </html>
    """

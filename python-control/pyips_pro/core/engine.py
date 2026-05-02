import asyncio
import json
from pathlib import Path
from typing import List, Dict, Optional
import redis.asyncio as redis
from datetime import datetime

# Import Rust core via PyO3
try:
    from pyips_core import PyIPSEngine as RustEngine
except ImportError:
    print("ERROR: Rust core not compiled. Run: cd rust-core && maturin develop")
    raise

from ..utils.logger import get_logger
from ..utils.metrics import record_metric
from ..storage.timescale import TimescaleDB

logger = get_logger(__name__)

class PyIPSProEngine:
    def __init__(self, config_path: Path):
        self.config = self._load_config(config_path)
        self.rust_engine: Optional[RustEngine] = None
        self.redis_client: Optional[redis.Redis] = None
        self.tsdb: Optional[TimescaleDB] = None
        self.running = False
        
    def _load_config(self, path: Path) -> dict:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)
    
    async def start(self):
        logger.info("Starting PyIPS-Pro Engine")
        
        # Initialize connections
        self.redis_client = await redis.from_url(
            self.config["redis"]["url"],
            decode_responses=True
        )
        self.tsdb = TimescaleDB(self.config["timescale"])
        await self.tsdb.init()
        
        # Initialize Rust engine
        self.rust_engine = RustEngine(
            self.config["network"]["interface"],
            self.config["rules"]["path"]
        )
        
        # Load ML model
        from .ml_detector import MLDetector
        self.ml_detector = MLDetector(self.config["ml"]["model_path"])
        
        # Start async tasks
        asyncio.create_task(self._health_check())
        asyncio.create_task(self._sync_stats())
        asyncio.create_task(self._process_alerts())
        
        # Start Rust engine (blocking in Rust thread)
        await asyncio.to_thread(self.rust_engine.start)
        
    async def _health_check(self):
        while self.running:
            stats = self.rust_engine.get_stats()
            await self.redis_client.hset("pyips:health", mapping=stats)
            await asyncio.sleep(5)
    
    async def _sync_stats(self):
        while self.running:
            stats = self.rust_engine.get_stats()
            await self.tsdb.insert_metrics(stats)
            record_metric("packets_per_sec", stats.get("packets_processed", 0))
            await asyncio.sleep(60)
    
    async def _process_alerts(self):
        while self.running:
            alerts = await self.redis_client.lpop("pyips:alerts", count=100)
            if alerts:
                for alert in alerts:
                    alert_data = json.loads(alert)
                    await self._handle_alert(alert_data)
            await asyncio.sleep(0.1)
    
    async def _handle_alert(self, alert: dict):
        logger.warning(f"Alert: {alert['rule_id']} from {alert['src_ip']}")
        
        # Store in TimescaleDB
        await self.tsdb.insert_alert(alert)
        
        # Check if ML model flags as critical
        ml_score = await self.ml_detector.predict(alert)
        
        if ml_score > 0.9 or alert["severity"] == "critical":
            self.rust_engine.block_ip(
                alert["src_ip"],
                f"ML={ml_score}, rule={alert['rule_id']}"
            )
            
            # Send to MISP if configured
            if self.config["misp"]["enabled"]:
                await self._send_to_misp(alert)
    
    async def _send_to_misp(self, alert: dict):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.config['misp']['url']}/events",
                headers={"Authorization": self.config["misp"]["api_key"]},
                json={"Event": alert}
            )
    
    async def block_ip(self, ip: str, reason: str, duration_sec: int = 3600) -> bool:
        result = self.rust_engine.block_ip(ip, reason)
        
        if result:
            await self.tsdb.insert_block({
                "ip": ip,
                "reason": reason,
                "duration": duration_sec,
                "timestamp": datetime.utcnow()
            })
            
            # Also block in nftables as backup
            await self._block_nftables(ip)
        
        return result
    
    async def _block_nftables(self, ip: str):
        proc = await asyncio.create_subprocess_exec(
            "nft", "add", "rule", "inet", "filter", "input",
            "ip", "saddr", ip, "drop"
        )
        await proc.wait()
    
    async def stop(self):
        self.running = False
        await self.redis_client.close()
        await self.tsdb.close()
        logger.info("PyIPS-Pro stopped")

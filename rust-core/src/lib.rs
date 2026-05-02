use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::sync::Arc;
use tokio::sync::RwLock;

mod packet;
mod detection;
mod blocking;
mod ffi;

use packet::capture::XDPCapture;
use detection::ac::AhoCorasickMatcher;
use detection::ja3::JA3Extractor;
use detection::anomaly::AnomalyDetector;
use blocking::xdp::XDPBlocker;

#[pyclass]
pub struct PyIPSEngine {
    capture: Arc<XDPCapture>,
    matcher: Arc<AhoCorasickMatcher>,
    ja3: Arc<JA3Extractor>,
    anomaly: Arc<AnomalyDetector>,
    blocker: Arc<XDPBlocker>,
    stats: Arc<RwLock<EngineStats>>,
}

#[pymethods]
impl PyIPSEngine {
    #[new]
    fn new(interface: String, rules_path: String) -> PyResult<Self> {
        Ok(Self {
            capture: Arc::new(XDPCapture::new(&interface).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?),
            matcher: Arc::new(AhoCorasickMatcher::from_file(&rules_path)?),
            ja3: Arc::new(JA3Extractor::new()),
            anomaly: Arc::new(AnomalyDetector::new()),
            blocker: Arc::new(XDPBlocker::new(&interface)?),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        })
    }

    fn start(&self, py: Python) -> PyResult<()> {
        let stats = self.stats.clone();
        let matcher = self.matcher.clone();
        let ja3 = self.ja3.clone();
        let anomaly = self.anomaly.clone();
        let blocker = self.blocker.clone();
        
        pyo3_asyncio::tokio::run(py, async move {
            let mut capture = (*capture).clone();
            
            while let Some(packet) = capture.next_packet().await {
                tokio::spawn(process_packet(packet, matcher.clone(), ja3.clone(), anomaly.clone(), blocker.clone(), stats.clone()));
            }
            
            Ok(())
        })
    }

    fn block_ip(&self, ip: String, reason: String) -> PyResult<bool> {
        Ok(self.blocker.block_ip(&ip, &reason))
    }

    fn unblock_ip(&self, ip: String) -> PyResult<bool> {
        Ok(self.blocker.unblock_ip(&ip))
    }

    fn get_stats(&self) -> PyResult<PyObject> {
        let stats = Python::with_gil(|py| {
            let dict = PyDict::new(py);
            let runtime_stats = self.stats.blocking_read();
            dict.set_item("packets_processed", runtime_stats.packets_processed)?;
            dict.set_item("alerts", runtime_stats.alerts)?;
            dict.set_item("blocks", runtime_stats.blocks)?;
            dict.set_item("avg_latency_ns", runtime_stats.avg_latency_ns)?;
            Ok(dict)
        })?;
        Ok(stats)
    }

    fn reload_rules(&mut self, rules_path: String) -> PyResult<()> {
        self.matcher = Arc::new(AhoCorasickMatcher::from_file(&rules_path)?);
        Ok(())
    }
}

#[derive(Default)]
struct EngineStats {
    packets_processed: u64,
    alerts: u64,
    blocks: u64,
    avg_latency_ns: u64,
}

async fn process_packet(
    packet: packet::RawPacket,
    matcher: Arc<AhoCorasickMatcher>,
    ja3: Arc<JA3Extractor>,
    anomaly: Arc<AnomalyDetector>,
    blocker: Arc<XDPBlocker>,
    stats: Arc<RwLock<EngineStats>>,
) {
    let start = std::time::Instant::now();
    
    // Parse packet layers
    let parsed = packet::parser::parse(&packet.data);
    
    // Check signatures (Aho-Corasick)
    let signatures = matcher.search(&packet.data);
    
    // Extract JA3 if TLS
    let ja3_hash = if parsed.is_tls() {
        ja3.extract(&packet.data)
    } else {
        None
    };
    
    // Anomaly score
    let anomaly_score = anomaly.evaluate(&parsed);
    
    // Decision
    let should_block = !signatures.is_empty() || anomaly_score > 0.85;
    
    if should_block {
        blocker.block_ip(&parsed.src_ip, format!("signatures={:?}, anomaly={}", signatures, anomaly_score).as_str());
        
        let mut stats = stats.write().await;
        stats.blocks += 1;
        stats.alerts += signatures.len() as u64;
    }
    
    let mut stats = stats.write().await;
    stats.packets_processed += 1;
    stats.avg_latency_ns = (stats.avg_latency_ns + start.elapsed().as_nanos() as u64) / 2;
}

/// PyO3 module definition
#[pymodule]
fn pyips_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyIPSEngine>()?;
    Ok(())
}

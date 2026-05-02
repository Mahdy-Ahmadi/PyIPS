use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::time::{Duration, sleep};

pub struct XDPBlocker {
    blocked_ips: RwLock<HashMap<IpAddr, BlockEntry>>,
    interface: String,
}

struct BlockEntry {
    reason: String,
    timestamp: std::time::Instant,
    expiry: Option<Duration>,
}

impl XDPBlocker {
    pub fn new(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            blocked_ips: RwLock::new(HashMap::new()),
            interface: interface.to_string(),
        })
    }
    
    pub fn block_ip(&self, ip: &IpAddr, reason: &str) -> bool {
        let mut blocked = self.blocked_ips.write().unwrap();
        
        let entry = BlockEntry {
            reason: reason.to_string(),
            timestamp: std::time::Instant::now(),
            expiry: Some(Duration::from_secs(3600)),
        };
        
        blocked.insert(*ip, entry);
        self.apply_xdp_block(ip);
        
        true
    }
    
    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        let mut blocked = self.blocked_ips.write().unwrap();
        blocked.remove(ip);
        self.apply_xdp_unblock(ip);
        
        true
    }
    
    fn apply_xdp_block(&self, ip: &IpAddr) {
        let cmd = format!(
            "bpftool cgroup attach /sys/fs/cgroup/unified/ ingress pinned /sys/fs/bpf/xdp/block_{}",
            ip
        );
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output();
    }
    
    fn apply_xdp_unblock(&self, ip: &IpAddr) {
        let cmd = format!(
            "bpftool cgroup detach /sys/fs/cgroup/unified/ ingress pinned /sys/fs/bpf/xdp/block_{}",
            ip
        );
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output();
    }
}

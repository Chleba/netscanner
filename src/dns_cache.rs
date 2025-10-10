use dns_lookup::lookup_addr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const CACHE_SIZE: usize = 1000;
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Clone, Debug)]
struct CacheEntry {
    hostname: String,
    timestamp: Instant,
}

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<IpAddr, CacheEntry>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Lookup hostname with timeout and caching
    pub async fn lookup_with_timeout(&self, ip: IpAddr) -> String {
        // Check cache first
        if let Some(hostname) = self.get_cached(&ip) {
            return hostname;
        }

        // Perform DNS lookup with timeout
        let ip_for_task = ip;
        let lookup_result = tokio::time::timeout(DNS_TIMEOUT, tokio::task::spawn_blocking(move || {
            lookup_addr(&ip_for_task)
        }))
        .await;

        let hostname = match lookup_result {
            Ok(Ok(Ok(name))) => name,
            _ => String::new(), // Timeout, task error, or lookup error - return empty
        };

        // Cache the result (even if empty to avoid repeated lookups)
        self.cache_result(ip, hostname.clone());

        hostname
    }

    /// Get cached hostname if available and not expired
    fn get_cached(&self, ip: &IpAddr) -> Option<String> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(ip) {
                if entry.timestamp.elapsed() < CACHE_TTL {
                    return Some(entry.hostname.clone());
                }
            }
        }
        None
    }

    /// Cache a lookup result
    fn cache_result(&self, ip: IpAddr, hostname: String) {
        if let Ok(mut cache) = self.cache.lock() {
            // Evict oldest entry if cache is full
            if cache.len() >= CACHE_SIZE {
                if let Some(oldest_ip) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.timestamp)
                    .map(|(ip, _)| *ip)
                {
                    cache.remove(&oldest_ip);
                }
            }

            cache.insert(
                ip,
                CacheEntry {
                    hostname,
                    timestamp: Instant::now(),
                },
            );
        }
    }

    /// Synchronous lookup without timeout (for compatibility, not recommended)
    pub fn lookup_sync(&self, ip: IpAddr) -> String {
        // Check cache first
        if let Some(hostname) = self.get_cached(&ip) {
            return hostname;
        }

        // Perform lookup without timeout (fallback)
        let hostname = lookup_addr(&ip).unwrap_or_default();
        self.cache_result(ip, hostname.clone());
        hostname
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

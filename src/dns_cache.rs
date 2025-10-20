//! Thread-safe DNS caching with timeout and TTL support.
//!
//! This module provides [`DnsCache`], a high-performance DNS resolver with:
//! - **Timeout Protection**: 2-second limit per lookup to prevent blocking
//! - **LRU-style Caching**: Stores up to 1000 entries, evicting oldest on overflow
//! - **TTL Expiration**: Cached entries expire after 5 minutes
//! - **Thread Safety**: Safe to clone and share across async tasks
//!
//! # Performance Characteristics
//!
//! - **Cache Hit**: ~1 microsecond (mutex lock + HashMap lookup)
//! - **Cache Miss**: Up to 2 seconds (DNS lookup with timeout)
//! - **Memory**: ~100 bytes per cached entry
//!
//! # Usage Example
//!
//! ```rust
//! use std::net::IpAddr;
//! use netscanner::dns_cache::DnsCache;
//!
//! # async fn example() {
//! let cache = DnsCache::new();
//!
//! // First lookup performs DNS query (slow)
//! let hostname = cache.lookup_with_timeout("8.8.8.8".parse().unwrap()).await;
//!
//! // Subsequent lookups use cache (fast)
//! let cached = cache.lookup_with_timeout("8.8.8.8".parse().unwrap()).await;
//! # }
//! ```
//!
//! # Thread Safety
//!
//! `DnsCache` is designed to be cloned and shared across components:
//! - Cloning is cheap (only clones an `Arc`)
//! - All clones share the same underlying cache
//! - Mutex ensures thread-safe concurrent access

use dns_lookup::lookup_addr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum time to wait for a DNS lookup before giving up.
/// Prevents slow/unresponsive DNS servers from blocking the UI.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of cached DNS entries before eviction starts.
/// Using LRU eviction: oldest entry by timestamp is removed first.
const CACHE_SIZE: usize = 1000;

/// Time-to-live for cached DNS entries.
/// After 5 minutes, entries are considered stale and will be re-queried.
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Internal cache entry storing a hostname and its lookup timestamp.
#[derive(Clone, Debug)]
struct CacheEntry {
    hostname: String,
    timestamp: Instant,
}

/// Thread-safe DNS cache with timeout and TTL support.
///
/// This cache is designed for high-performance reverse DNS lookups in network
/// scanning scenarios where:
/// - Multiple concurrent lookups may occur
/// - DNS servers may be slow or unresponsive
/// - Many IPs are looked up repeatedly
///
/// # Cloning
///
/// Cloning is cheap and all clones share the same underlying cache via `Arc`.
/// This allows components to independently own a cache instance while sharing
/// the cached data.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<IpAddr, CacheEntry>>>,
}

impl DnsCache {
    /// Creates a new empty DNS cache.
    ///
    /// This is cheap to call multiple times - use [`clone()`](DnsCache::clone)
    /// to share an existing cache across components.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Performs a reverse DNS lookup with timeout and caching.
    ///
    /// This is the recommended method for DNS lookups. It:
    /// 1. Checks the cache for a recent result
    /// 2. If not cached, performs a blocking DNS lookup in a separate task
    /// 3. Times out after 2 seconds if DNS is slow/unavailable
    /// 4. Caches the result (even if empty) to avoid repeated lookups
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to look up
    ///
    /// # Returns
    ///
    /// Returns the hostname as a String, or an empty String if:
    /// - The lookup timed out
    /// - No reverse DNS record exists
    /// - DNS server is unavailable
    ///
    /// # Example
    ///
    /// ```rust
    /// # use netscanner::dns_cache::DnsCache;
    /// # async fn example() {
    /// let cache = DnsCache::new();
    /// let hostname = cache.lookup_with_timeout("8.8.8.8".parse().unwrap()).await;
    /// println!("8.8.8.8 resolved to: {}", hostname);
    /// # }
    /// ```
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

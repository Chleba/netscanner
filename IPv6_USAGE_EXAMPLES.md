# IPv6 Usage Examples for netscanner

## Quick Start

netscanner now supports full IPv6 network scanning. This guide provides practical examples for using IPv6 features.

## Prerequisites

- Root/sudo privileges (required for raw socket access)
- Network interface with IPv6 enabled
- IPv6 connectivity (local or internet)

## Basic Usage

### 1. IPv6 Link-Local Network Scan

Link-local addresses (fe80::/10) are automatically assigned to all IPv6-enabled interfaces:

```bash
sudo netscanner
# In the Discovery tab:
# 1. Press 'i' to enter input mode
# 2. Enter: fe80::1:2:3:0/120
# 3. Press Enter, then 's' to scan
```

**What this does:**
- Scans 256 IPv6 addresses in the fe80::1:2:3:0/120 range
- Sends ICMPv6 Echo Request packets
- Displays responding hosts with hostnames (if DNS is available)

### 2. IPv6 Global Unicast Scan

For global IPv6 addresses:

```bash
sudo netscanner
# In the Discovery tab:
# 1. Press 'i' to enter input mode
# 2. Enter: 2001:db8::100:0/120
# 3. Press Enter, then 's' to scan
```

**Note:** Replace `2001:db8::` with your actual IPv6 network prefix.

### 3. IPv6 Port Scanning

After discovering IPv6 hosts:

```bash
# 1. Complete a network scan (IPv4 or IPv6)
# 2. Press '3' or Tab to switch to the Ports tab
# 3. Use arrow keys to select an IPv6 host
# 4. Press 's' to scan common ports
```

**Scanned ports:**
- Common ports (22, 80, 443, 3389, etc.) are automatically scanned
- Results show service names (SSH, HTTP, HTTPS, etc.)
- Works identically for IPv4 and IPv6 hosts

### 4. Mixed IPv4/IPv6 Environment

netscanner handles dual-stack networks seamlessly:

```bash
# Scan IPv4 network
Enter: 192.168.1.0/24

# Then switch to IPv6
Press 'i'
Enter: fe80::1:2:3:0/120
Press 's'

# Results will show both IPv4 and IPv6 hosts
# IPv4 hosts appear first, followed by IPv6 hosts
```

## IPv6 Address Formats Supported

### Valid Input Examples

```
fe80::1/120                    # Link-local with host bits
fe80::1:2:3:4/120              # Link-local expanded
2001:db8::1/120                # Global unicast
2001:0db8:85a3::8a2e:0370:7334/120  # Fully expanded
::1/128                        # Loopback (rejected - not scannable)
```

### Invalid Input Examples

```
fe80::/64                      # Too large (2^64 addresses)
fe80::/10                      # Much too large (rejected)
ff02::1/120                    # Multicast (rejected)
::1/128                        # Loopback (rejected)
```

## Limitations

### 1. Prefix Size Restrictions

**Minimum prefix: /120 (256 addresses)**

IPv6 networks are designed to be extremely large. A typical /64 network contains 18,446,744,073,709,551,616 addresses, which is impractical to scan.

**Workaround:**
- Focus on specific subnets (e.g., fe80::1:0/120)
- Scan known address ranges
- Use smaller, targeted scans

### 2. MAC Address Resolution

**Not implemented:** NDP (Neighbor Discovery Protocol)

IPv6 uses NDP instead of ARP for MAC address resolution. The current implementation does not include NDP support.

**Impact:**
- IPv6 hosts will not show MAC addresses
- Vendor information will not be available for IPv6 hosts
- IPv4 hosts continue to show MAC addresses via ARP

**Future work:** NDP implementation is planned

### 3. Performance Considerations

**Scan speed:**
- IPv6 scans take approximately the same time as IPv4
- Default timeout: 2 seconds per host
- Concurrent scan pool: 16-64 threads (based on CPU cores)

**For a /120 network (256 addresses):**
- Estimated time: 10-20 seconds
- Depends on network latency and host response

## Common IPv6 Scenarios

### Home Network (ISP-provided IPv6)

Most ISPs provide a /56 or /64 prefix. To scan a portion:

```bash
# If your prefix is 2001:db8:1234::/48
# Scan a small subnet:
2001:db8:1234:1::0/120
```

### Corporate Network

```bash
# Scan specific server subnet
2001:db8:abcd:ef01::0/120
```

### Virtual Machine Host

```bash
# Scan libvirt default IPv6 network
fd00::/120
```

### Docker IPv6 Network

```bash
# Scan Docker IPv6 subnet
fd00:dead:beef::0/120
```

## Troubleshooting

### No IPv6 Hosts Found

**Check IPv6 connectivity:**
```bash
ping6 google.com
ip -6 addr show
```

**Verify firewall allows ICMPv6:**
```bash
# Linux
sudo ip6tables -L -n | grep icmp

# macOS
sudo pfctl -sr | grep icmp6
```

### CIDR Parse Error

**Possible causes:**
1. Prefix too small (< /120)
2. Invalid IPv6 format
3. Multicast or loopback address

**Solution:**
- Use /120 or larger prefix
- Verify address format (use :: compression)
- Check for typos in address

### Permission Denied

**All network scanning requires root:**
```bash
sudo netscanner
```

## Advanced Tips

### 1. Finding Your IPv6 Prefix

```bash
# Linux
ip -6 addr show | grep inet6

# macOS
ifconfig | grep inet6

# Output example:
inet6 2001:db8:1234:5678::1/64
      ^^^^^^^^^^^^^^^^^^^^^^^^^^ Your prefix
```

### 2. Scanning Multiple Subnets

Run netscanner multiple times or use the clear function:

```bash
# Scan first subnet
Enter: 2001:db8::100:0/120
Press 's'

# Clear and scan next
Press 'c' (clear)
Press 'i'
Enter: 2001:db8::200:0/120
Press 's'
```

### 3. Exporting IPv6 Results

```bash
# After scanning, press 'e' to export
# CSV file includes:
# - IPv6 addresses (full notation)
# - Hostnames
# - No MAC addresses (NDP not implemented)
```

## Comparison: IPv4 vs IPv6

| Feature | IPv4 | IPv6 |
|---------|------|------|
| Scanning | ✅ /16 to /32 | ✅ /120 to /128 |
| Ping | ✅ ICMP | ✅ ICMPv6 |
| Port Scan | ✅ TCP | ✅ TCP |
| MAC Address | ✅ ARP | ❌ NDP (pending) |
| DNS Lookup | ✅ | ✅ |
| Traffic Mon | ✅ | ✅ |

## Example Session

```
┌─────────────────────────────────────────────────────────┐
│ netscanner - Network Discovery & Port Scanner           │
├─────────────────────────────────────────────────────────┤
│ [Discovery]                                             │
│                                                         │
│ Input: fe80::1:2:3:0/120                   [scanning..] │
│                                                         │
│ IP                      MAC               Hostname      │
│ ─────────────────────────────────────────────────────── │
│ fe80::1:2:3:1          (no MAC)          homeserver    │
│ fe80::1:2:3:5          (no MAC)          laptop        │
│ fe80::1:2:3:10         (no MAC)          printer       │
│                                                         │
│ ◉ 3 hosts found | ⣿(256/256) scanned                   │
└─────────────────────────────────────────────────────────┘
```

## Support

For issues or questions:
- GitHub: https://github.com/Chleba/netscanner/issues
- Refer to IPv6_IMPLEMENTATION_SUMMARY.md for technical details

## Future IPv6 Features

Planned for future releases:
1. NDP support for MAC address resolution
2. DHCPv6 server detection
3. IPv6 multicast group detection
4. Configurable prefix size limits
5. IPv6 flow label analysis

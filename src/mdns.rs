//! Reverse hostname lookup with an mDNS fallback for hosts on a local subnet.
//! Needed because the minimal nss-mdns plug-in only reverse-resolves 169.254.0.0/16.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use dns_lookup::lookup_addr;
use ipnetwork::IpNetwork;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const MDNS_TIMEOUT: Duration = Duration::from_millis(1500);
const TYPE_PTR: u16 = 12;

/// Returns the best hostname for `ip`, or `None` if none is found.
pub async fn resolve_hostname(ip: IpAddr) -> Option<String> {
    let dns = tokio::task::spawn_blocking(move || lookup_addr(&ip).ok())
        .await
        .ok()
        .flatten();
    if dns.is_some() {
        return dns;
    }
    // mDNS is link-local: only query hosts inside a local interface's subnet.
    match ip {
        IpAddr::V4(v4) if local_addr_on_link(v4).is_some() => {
            mdns_reverse_lookup(v4, MDNS_TIMEOUT).await
        }
        _ => None,
    }
}

pub async fn mdns_reverse_lookup(ip: Ipv4Addr, wait: Duration) -> Option<String> {
    let o = ip.octets();
    let qname = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let id: u16 = rand::random();
    let query = build_ptr_query(id, &qname);

    let sock = mdns_socket(ip).ok()?;
    // Either send may fail (e.g. no multicast route); one success is enough.
    let unicast = sock.send_to(&query, (ip, MDNS_PORT)).await.is_ok();
    let multicast = sock.send_to(&query, (MDNS_GROUP, MDNS_PORT)).await.is_ok();
    if !unicast && !multicast {
        return None;
    }

    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 9000];
    loop {
        let (len, _from): (usize, SocketAddr) = timeout_at(deadline, sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        if let Some(name) = parse_ptr_answer(&buf[..len], &qname) {
            return Some(name);
        }
    }
}

/// A socket whose multicast leaves on the interface whose subnet contains `target`,
/// rather than whichever interface holds the 224.0.0.0/4 route.
fn mdns_socket(target: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    sock.set_multicast_ttl_v4(255)?;
    if let Some(local) = local_addr_on_link(target) {
        sock.set_multicast_if_v4(&local)?;
    }
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    UdpSocket::from_std(sock.into())
}

fn local_addr_on_link(target: Ipv4Addr) -> Option<Ipv4Addr> {
    pnet::datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ips)
        .find_map(|net| match net {
            IpNetwork::V4(n) if n.contains(target) => Some(n.ip()),
            _ => None,
        })
}

fn build_ptr_query(id: u16, qname: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags 0, QDCOUNT 1
    for label in qname.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&TYPE_PTR.to_be_bytes());
    p.extend_from_slice(&0x8001u16.to_be_bytes()); // class IN with the QU (unicast-response) bit
    p
}

/// Finds a PTR record for `qname` in the answer, authority or additional sections.
fn parse_ptr_answer(pkt: &[u8], qname: &str) -> Option<String> {
    if pkt.len() < 12 || pkt[2] & 0x80 == 0 {
        return None; // not a response
    }
    let count = |i: usize| u16::from_be_bytes([pkt[i], pkt[i + 1]]) as usize;
    let (qd, records) = (count(4), count(6) + count(8) + count(10));

    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(pkt, pos)?.1 + 4;
    }
    for _ in 0..records {
        let (name, next) = read_name(pkt, pos)?;
        let hdr = pkt.get(next..next + 10)?;
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        let rdata = next + 10;
        if rdata + rdlen > pkt.len() {
            return None;
        }
        if rtype == TYPE_PTR && name.eq_ignore_ascii_case(qname) {
            let target = read_name(pkt, rdata)?.0;
            if !target.is_empty() {
                return Some(target);
            }
        }
        pos = rdata + rdlen;
    }
    None
}

/// Reads a possibly compressed name at `pos`; returns it (no trailing dot) and the
/// offset just past it in the original stream.
fn read_name(pkt: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *pkt.get(pos)? as usize;
        match len {
            0 => {
                let after = end.unwrap_or(pos + 1);
                return Some((labels.join("."), after));
            }
            l if l & 0xC0 == 0xC0 => {
                let ptr = ((l & 0x3F) << 8) | *pkt.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                pos = ptr;
            }
            l if l < 64 => {
                let label = pkt.get(pos + 1..pos + 1 + l)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos += 1 + l;
            }
            _ => return None,
        }
    }
    None // pointer loop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ptr_answer() {
        let qname = "5.1.168.192.in-addr.arpa";
        let mut pkt = build_ptr_query(0, qname);
        pkt[2] = 0x84; // response, authoritative
        pkt[4..12].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // QD 0, AN 1
        pkt.truncate(12);
        for l in qname.split('.') {
            pkt.push(l.len() as u8);
            pkt.extend_from_slice(l.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let rd = [&[7u8][..], b"printer", &[5], b"local", &[0]].concat();
        pkt.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rd);
        assert_eq!(
            parse_ptr_answer(&pkt, qname).as_deref(),
            Some("printer.local")
        );
        assert_eq!(parse_ptr_answer(&pkt, "6.1.168.192.in-addr.arpa"), None);
    }

    #[test]
    fn follows_compression_pointer() {
        // name "a.local" at 12, then pointer to it at 21
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[1, b'a', 5, b'l', b'o', b'c', b'a', b'l', 0]);
        pkt.extend_from_slice(&[0xC0, 12]);
        assert_eq!(read_name(&pkt, 21), Some(("a.local".into(), 23)));
    }
}

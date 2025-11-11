use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use ipnetwork::IpNetwork;

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmpv6::{checksum, echo_request, Icmpv6Types};
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::sync::Semaphore;

use core::str;
use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence};
use tokio::{
    sync::mpsc::Sender,
    task::JoinHandle,
};

use super::Component;
use crate::{
    action::Action,
    components::packetdump::ArpPacketData,
    config::DEFAULT_BORDER_STYLE,
    dns_cache::DnsCache,
    enums::TabsEnum,
    layout::get_vertical_layout,
    mode::Mode,
    tui::Frame,
    utils::{count_ipv4_net_length, count_ipv6_net_length, get_ips4_from_cidr, get_ips6_from_cidr},
};
use crossterm::event::Event;
use crossterm::event::{KeyCode, KeyEvent};
use mac_oui::Oui;
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

const _DEFAULT_POOL_SIZE: usize = 32;
const MIN_POOL_SIZE: usize = 16;
const MAX_POOL_SIZE: usize = 64;
const PING_TIMEOUT_SECS: u64 = 2;
const INPUT_SIZE: usize = 30;
const DEFAULT_IP: &str = "192.168.1.0/24";
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Clone, Debug, PartialEq)]
pub struct ScannedIp {
    pub ip: String,
    pub ip_addr: IpAddr,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
}

pub struct Discovery {
    active_tab: TabsEnum,
    active_interface: Option<NetworkInterface>,
    action_tx: Option<Sender<Action>>,
    scanned_ips: Vec<ScannedIp>,
    ip_num: i32,
    input: Input,
    cidr: Option<IpNetwork>,
    cidr_error: bool,
    is_scanning: bool,
    mode: Mode,
    task: JoinHandle<()>,
    oui: Option<Oui>,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
    dns_cache: DnsCache,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            active_interface: None,
            task: tokio::spawn(async {}),
            action_tx: None,
            scanned_ips: Vec::new(),
            ip_num: 0,
            input: Input::default().with_value(String::from(DEFAULT_IP)),
            cidr: None,
            cidr_error: false,
            is_scanning: false,
            mode: Mode::Normal,
            oui: None,
            table_state: TableState::default().with_selected(0),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
            dns_cache: DnsCache::new(),
        }
    }

    fn get_pool_size() -> usize {
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let calculated = num_cpus * 2;
        calculated.clamp(MIN_POOL_SIZE, MAX_POOL_SIZE)
    }

    // Prefers global unicast addresses over link-local for proper routing
    fn get_interface_ipv6(interface: &NetworkInterface) -> Option<Ipv6Addr> {
        let mut link_local = None;

        for ip_network in &interface.ips {
            if let IpAddr::V6(ipv6_addr) = ip_network.ip() {
                if ipv6_addr.is_loopback() || ipv6_addr.is_multicast() {
                    continue;
                }

                if !Self::is_link_local_ipv6(&ipv6_addr) {
                    return Some(ipv6_addr);
                }

                if link_local.is_none() {
                    link_local = Some(ipv6_addr);
                }
            }
        }

        link_local
    }

    fn is_link_local_ipv6(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        (segments[0] & 0xffc0) == 0xfe80
    }

    fn is_macos() -> bool {
        cfg!(target_os = "macos")
    }

    // macOS kernel doesn't deliver ICMPv6 Echo Replies to user-space
    async fn ping6_system_command(target_ipv6: Ipv6Addr, timeout_secs: u64) -> bool {
        use tokio::process::Command;
        use tokio::time::timeout;
        use std::time::Duration;

        let mut cmd = Command::new("ping6");
        cmd.arg("-c").arg("1");

        #[cfg(target_os = "linux")]
        {
            cmd.arg("-W").arg(timeout_secs.to_string());
        }

        cmd.arg(target_ipv6.to_string());

        let result = timeout(
            Duration::from_secs(timeout_secs + 1),
            cmd.output()
        ).await;

        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    log::debug!("ping6 success for {}", target_ipv6);
                    true
                } else {
                    log::debug!("ping6 no response from {}", target_ipv6);
                    false
                }
            }
            Ok(Err(e)) => {
                log::debug!("Failed to execute ping6 command: {:?}", e);
                false
            }
            Err(_) => {
                log::debug!("ping6 command timed out for {}", target_ipv6);
                false
            }
        }
    }

    async fn send_icmpv6_echo_request(
        interface: &NetworkInterface,
        source_ipv6: Ipv6Addr,
        target_ipv6: Ipv6Addr,
        identifier: u16,
        sequence: u16,
    ) -> Result<(), String> {
        let (mut tx, _) = match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unknown channel type".to_string()),
            Err(e) => return Err(format!("Failed to create datalink channel: {}", e)),
        };

        // Packet structure: [Ethernet Header (14 bytes)] [IPv6 Header (40 bytes)] [ICMPv6 Echo Request (8 bytes + payload)]
        const ETHERNET_HEADER_LEN: usize = 14;
        const IPV6_HEADER_LEN: usize = 40;
        const ICMPV6_HEADER_LEN: usize = 8;
        const PAYLOAD_LEN: usize = 56;
        const TOTAL_LEN: usize = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_HEADER_LEN + PAYLOAD_LEN;

        let mut ethernet_buffer = [0u8; TOTAL_LEN];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or("Failed to create Ethernet packet")?;

        ethernet_packet.set_destination(pnet::util::MacAddr::broadcast());
        ethernet_packet.set_source(interface.mac.unwrap_or(pnet::util::MacAddr::zero()));
        ethernet_packet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6_buffer = [0u8; IPV6_HEADER_LEN + ICMPV6_HEADER_LEN + PAYLOAD_LEN];
        let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer)
            .ok_or("Failed to create IPv6 packet")?;

        ipv6_packet.set_payload_length((ICMPV6_HEADER_LEN + PAYLOAD_LEN) as u16);
        ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        ipv6_packet.set_hop_limit(64);
        ipv6_packet.set_source(source_ipv6);
        ipv6_packet.set_destination(target_ipv6);

        let mut icmpv6_buffer = [0u8; ICMPV6_HEADER_LEN + PAYLOAD_LEN];

        use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
        let mut echo_request_packet = MutableEchoRequestPacket::new(&mut icmpv6_buffer)
            .ok_or("Failed to create Echo Request packet")?;

        echo_request_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        echo_request_packet.set_icmpv6_code(echo_request::Icmpv6Codes::NoCode);
        echo_request_packet.set_identifier(identifier);
        echo_request_packet.set_sequence_number(sequence);

        use pnet::packet::icmpv6::Icmpv6Packet;
        let icmpv6_for_checksum = Icmpv6Packet::new(echo_request_packet.packet())
            .ok_or("Failed to create Icmpv6Packet for checksum")?;
        let checksum_val = checksum(&icmpv6_for_checksum, &source_ipv6, &target_ipv6);
        echo_request_packet.set_checksum(checksum_val);

        ipv6_packet.set_payload(echo_request_packet.packet());
        ethernet_packet.set_payload(ipv6_packet.packet());

        // Yield to tokio scheduler before blocking I/O
        tokio::task::yield_now().await;
        tx.send_to(ethernet_packet.packet(), None)
            .ok_or("Failed to send packet")?
            .map_err(|e| format!("Send error: {}", e))?;

        Ok(())
    }

    async fn receive_icmpv6_echo_reply(
        interface: &NetworkInterface,
        target_ipv6: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        timeout: Duration,
    ) -> Option<Ipv6Addr> {
        let (_, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return None,
            Err(e) => {
                log::debug!("Failed to create datalink channel for receiving: {}", e);
                return None;
            }
        };

        let result = tokio::time::timeout(timeout, async {
            loop {
                // Yield to tokio scheduler before blocking I/O
                tokio::task::yield_now().await;

                match rx.next() {
                    Ok(packet) => {
                        use pnet::packet::ethernet::EthernetPacket;
                        let eth_packet = match EthernetPacket::new(packet) {
                            Some(eth) => eth,
                            None => continue,
                        };

                        if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
                            continue;
                        }

                        use pnet::packet::ipv6::Ipv6Packet;
                        let ipv6_packet = match Ipv6Packet::new(eth_packet.payload()) {
                            Some(ipv6) => ipv6,
                            None => continue,
                        };

                        if ipv6_packet.get_source() != target_ipv6 {
                            continue;
                        }

                        use pnet::packet::ip::IpNextHeaderProtocols;
                        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                            continue;
                        }

                        use pnet::packet::icmpv6::Icmpv6Packet;
                        let icmpv6_packet = match Icmpv6Packet::new(ipv6_packet.payload()) {
                            Some(icmpv6) => icmpv6,
                            None => continue,
                        };

                        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::EchoReply {
                            continue;
                        }

                        use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
                        let echo_reply = match EchoReplyPacket::new(icmpv6_packet.packet()) {
                            Some(reply) => reply,
                            None => continue,
                        };

                        let reply_identifier = echo_reply.get_identifier();
                        let reply_sequence = echo_reply.get_sequence_number();

                        if reply_identifier == identifier && reply_sequence == sequence {
                            return Some(ipv6_packet.get_source());
                        }
                    }
                    Err(e) => {
                        log::debug!("Error receiving packet: {}", e);
                        continue;
                    }
                }
            }
        })
        .await;

        result.ok().flatten()
    }

    // RFC 4861 compliant Neighbor Discovery Protocol
    async fn send_neighbor_solicitation(
        interface: &NetworkInterface,
        source_ipv6: Ipv6Addr,
        target_ipv6: Ipv6Addr,
    ) -> Result<(), String> {
        let source_mac = interface.mac.ok_or("Interface has no MAC address".to_string())?;

        let target_segments = target_ipv6.segments();
        let solicited_node = Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 1,
            0xff00 | (target_segments[6] & 0x00ff),
            target_segments[7],
        );

        let multicast_mac = MacAddr::new(
            0x33, 0x33,
            ((solicited_node.segments()[6] >> 8) & 0xff) as u8,
            (solicited_node.segments()[6] & 0xff) as u8,
            ((solicited_node.segments()[7] >> 8) & 0xff) as u8,
            (solicited_node.segments()[7] & 0xff) as u8,
        );

        let mut ethernet_buffer = vec![0u8; 86];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or("Failed to create Ethernet packet".to_string())?;

        ethernet_packet.set_destination(multicast_mac);
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6_buffer = vec![0u8; 72];
        let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer)
            .ok_or("Failed to create IPv6 packet".to_string())?;

        ipv6_packet.set_version(6);
        ipv6_packet.set_traffic_class(0);
        ipv6_packet.set_flow_label(0);
        ipv6_packet.set_payload_length(32);
        ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        ipv6_packet.set_hop_limit(255);
        ipv6_packet.set_source(source_ipv6);
        ipv6_packet.set_destination(solicited_node);

        let mut icmpv6_buffer = vec![0u8; 32];
        let mut ns_packet = MutableNeighborSolicitPacket::new(&mut icmpv6_buffer)
            .ok_or("Failed to create Neighbor Solicit packet".to_string())?;

        ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ns_packet.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));
        ns_packet.set_reserved(0);
        ns_packet.set_target_addr(target_ipv6);

        let ndp_option = NdpOption {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: source_mac.octets().to_vec(),
        };
        ns_packet.set_options(&[ndp_option]);

        let checksum = pnet::packet::icmpv6::checksum(
            &pnet::packet::icmpv6::Icmpv6Packet::new(ns_packet.packet())
                .ok_or("Failed to create ICMPv6 packet for checksum".to_string())?,
            &source_ipv6,
            &solicited_node,
        );
        ns_packet.set_checksum(checksum);

        ipv6_packet.set_payload(ns_packet.packet());
        ethernet_packet.set_payload(ipv6_packet.packet());

        let (mut tx, _) = match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unsupported channel type".to_string()),
            Err(e) => return Err(format!("Failed to create datalink channel: {:?}", e)),
        };

        tx.send_to(ethernet_packet.packet(), None)
            .ok_or("Failed to send packet".to_string())?
            .map_err(|e| format!("Failed to send NDP packet: {:?}", e))?;

        log::debug!("Sent Neighbor Solicitation for {} from {}", target_ipv6, source_ipv6);
        Ok(())
    }

    async fn receive_neighbor_advertisement(
        interface: &NetworkInterface,
        target_ipv6: Ipv6Addr,
        timeout: Duration,
    ) -> Option<(Ipv6Addr, MacAddr)> {
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv6::Ipv6Packet;
        use tokio::time::{timeout as tokio_timeout, sleep};

        let (_tx, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                log::debug!("Unsupported channel type for NDP receive");
                return None;
            }
            Err(e) => {
                log::debug!("Failed to open datalink channel for NDP: {:?}", e);
                return None;
            }
        };

        let result = tokio_timeout(timeout, async {
            loop {
                tokio::task::yield_now().await;
                match rx.next() {
                    Ok(packet) => {
                        if let Some(eth_packet) = EthernetPacket::new(packet) {
                            if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
                                continue;
                            }

                            if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
                                if ipv6_packet.get_next_header() != pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 {
                                    continue;
                                }

                                if ipv6_packet.get_source() != target_ipv6 {
                                    continue;
                                }

                                if let Some(na_packet) = NeighborAdvertPacket::new(ipv6_packet.payload()) {
                                    if na_packet.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
                                        continue;
                                    }

                                    for option in na_packet.get_options() {
                                        if option.option_type == NdpOptionTypes::TargetLLAddr
                                            && option.length == 1
                                            && option.data.len() >= 6 {
                                            let mac = MacAddr::new(
                                                option.data[0],
                                                option.data[1],
                                                option.data[2],
                                                option.data[3],
                                                option.data[4],
                                                option.data[5],
                                            );
                                            log::debug!("Received Neighbor Advertisement from {} with MAC {}", target_ipv6, mac);
                                            return Some((target_ipv6, mac));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!("Error receiving packet for NDP: {:?}", e);
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }).await;

        match result {
            Ok(Some(result)) => Some(result),
            Ok(None) => None,
            Err(_) => {
                log::debug!("Timeout waiting for Neighbor Advertisement from {}", target_ipv6);
                None
            }
        }
    }

    pub fn get_scanned_ips(&self) -> &Vec<ScannedIp> {
        &self.scanned_ips
    }

    fn set_cidr(&mut self, cidr_str: String, scan: bool) {
        let trimmed = cidr_str.trim();
        if trimmed.is_empty() {
            if let Some(tx) = &self.action_tx {
                let _ = tx.clone().try_send(Action::CidrError);
            }
            return;
        }

        if !trimmed.contains('/') {
            if let Some(tx) = &self.action_tx {
                let _ = tx.clone().try_send(Action::CidrError);
            }
            return;
        }

        match trimmed.parse::<IpNetwork>() {
            Ok(ip_network) => {
                match ip_network {
                    IpNetwork::V4(ipv4_net) => {
                        let network_length = ipv4_net.prefix();

                        if network_length < 16 {
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }

                        let first_octet = ipv4_net.network().octets()[0];

                        if first_octet == 127 || first_octet >= 224 {
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }
                    }
                    IpNetwork::V6(ipv6_net) => {
                        let network_length = ipv6_net.prefix();

                        if network_length < 120 {
                            log::warn!("IPv6 network /{} is too large for scanning, minimum is /120", network_length);
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }

                        if ipv6_net.network().is_multicast()
                            || ipv6_net.network().is_loopback()
                            || ipv6_net.network().is_unspecified() {
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }
                    }
                }

                self.cidr = Some(ip_network);
                if scan {
                    self.scan();
                }
            }
            Err(_) => {
                if let Some(tx) = &self.action_tx {
                    let _ = tx.clone().try_send(Action::CidrError);
                }
            }
        }
    }

    fn reset_scan(&mut self) {
        self.scanned_ips.clear();
        self.ip_num = 0;
    }

    fn scan(&mut self) {
        self.reset_scan();

        if let Some(cidr) = self.cidr {
            self.is_scanning = true;

            let Some(tx) = self.action_tx.clone() else {
                self.is_scanning = false;
                return;
            };

            let interface = self.active_interface.clone();
            let pool_size = Self::get_pool_size();
            log::debug!("Using pool size of {} for discovery scan", pool_size);
            let semaphore = Arc::new(Semaphore::new(pool_size));

            self.task = tokio::spawn(async move {
                log::debug!("Starting CIDR scan task for {:?}", cidr);

                match cidr {
                    IpNetwork::V4(ipv4_cidr) => {
                        let cidr_str = format!("{}/{}", ipv4_cidr.network(), ipv4_cidr.prefix());
                        let Ok(ipv4_cidr_old) = cidr_str.parse::<Ipv4Cidr>() else {
                            log::error!("Failed to convert IPv4 CIDR for scanning");
                            let _ = tx.try_send(Action::CidrError);
                            return;
                        };

                        let ips = get_ips4_from_cidr(ipv4_cidr_old);
                        let tasks: Vec<_> = ips
                            .iter()
                            .map(|&ip| {
                                let s = semaphore.clone();
                                let tx = tx.clone();
                                let c = || async move {
                                    let Ok(_permit) = s.acquire().await else {
                                        let _ = tx.try_send(Action::CountIp);
                                        return;
                                    };
                                    let client = match Client::new(&Config::default()) {
                                        Ok(c) => c,
                                        Err(e) => {
                                            log::error!("Failed to create ICMP client: {:?}", e);
                                            let _ = tx.try_send(Action::CountIp);
                                            return;
                                        }
                                    };
                                    let payload = [0; 56];
                                    let mut pinger = client
                                        .pinger(IpAddr::V4(ip), PingIdentifier(random()))
                                        .await;
                                    pinger.timeout(Duration::from_secs(PING_TIMEOUT_SECS));

                                    match pinger.ping(PingSequence(2), &payload).await {
                                        Ok((IcmpPacket::V4(_packet), _dur)) => {
                                            tx.try_send(Action::PingIp(_packet.get_real_dest().to_string()))
                                                .unwrap_or_default();
                                            tx.try_send(Action::CountIp).unwrap_or_default();
                                        }
                                        Ok(_) => {
                                            tx.try_send(Action::CountIp).unwrap_or_default();
                                        }
                                        Err(_) => {
                                            tx.try_send(Action::CountIp).unwrap_or_default();
                                        }
                                    }
                                };
                                tokio::spawn(c())
                            })
                            .collect();
                        for t in tasks {
                            match t.await {
                                Ok(_) => {}
                                Err(e) if e.is_cancelled() => {
                                    log::debug!("Discovery scan task was cancelled for IPv4 CIDR range");
                                }
                                Err(e) if e.is_panic() => {
                                    log::error!(
                                        "Discovery scan task panicked while scanning IPv4 CIDR range: {:?}",
                                        e
                                    );
                                }
                                Err(e) => {
                                    log::error!(
                                        "Discovery scan task failed while scanning IPv4 CIDR range: {:?}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                    IpNetwork::V6(ipv6_cidr) => {
                        let ips = get_ips6_from_cidr(ipv6_cidr);
                        log::debug!("Scanning {} IPv6 addresses", ips.len());

                        let tasks: Vec<_> = ips
                            .iter()
                            .map(|&ip| {
                                let s = semaphore.clone();
                                let tx = tx.clone();
                                let interface_clone = interface.clone();
                                let c = || async move {
                                    let Ok(_permit) = s.acquire().await else {
                                        let _ = tx.try_send(Action::CountIp);
                                        return;
                                    };

                                    // macOS kernel doesn't deliver ICMPv6 Echo Replies to user-space
                                    let ping_success = if Self::is_macos() {
                                        log::debug!("Using system ping6 for {} (macOS)", ip);
                                        Self::ping6_system_command(ip, PING_TIMEOUT_SECS).await
                                    } else {
                                        log::debug!("Using manual ICMPv6 for {} (non-macOS)", ip);

                                        if let Some(source_ipv6) = interface_clone.as_ref().and_then(Self::get_interface_ipv6) {
                                            let identifier = random::<u16>();
                                            let sequence = 1u16;

                                            match Self::send_icmpv6_echo_request(
                                                interface_clone.as_ref().unwrap(),
                                                source_ipv6,
                                                ip,
                                                identifier,
                                                sequence
                                            ).await {
                                                Ok(()) => {
                                                    if let Some(target_ipv6) = Self::receive_icmpv6_echo_reply(
                                                        interface_clone.as_ref().unwrap(),
                                                        ip,
                                                        identifier,
                                                        sequence,
                                                        Duration::from_secs(PING_TIMEOUT_SECS)
                                                    ).await {
                                                        log::debug!("ICMPv6 Echo Reply received from {}", target_ipv6);
                                                        true
                                                    } else {
                                                        log::debug!("No ICMPv6 Echo Reply from {}", ip);
                                                        false
                                                    }
                                                }
                                                Err(e) => {
                                                    log::debug!("Failed to send ICMPv6 Echo Request to {}: {}", ip, e);
                                                    false
                                                }
                                            }
                                        } else {
                                            log::debug!("No IPv6 address on interface for pinging {}", ip);
                                            false
                                        }
                                    };

                                    if ping_success {
                                        tx.try_send(Action::PingIp(ip.to_string()))
                                            .unwrap_or_default();

                                        if let Some(ref interface_ref) = interface_clone {
                                            if let Some(source_ipv6) = Self::get_interface_ipv6(interface_ref) {
                                                log::debug!("Attempting NDP for {} from {}", ip, source_ipv6);

                                                match Self::send_neighbor_solicitation(interface_ref, source_ipv6, ip).await {
                                                    Ok(()) => {
                                                        if let Some((_ipv6, mac)) = Self::receive_neighbor_advertisement(
                                                            interface_ref,
                                                            ip,
                                                            Duration::from_secs(2)
                                                        ).await {
                                                            log::debug!("NDP discovered MAC {} for {}", mac, ip);
                                                            let _ = tx.try_send(Action::UpdateMac(
                                                                ip.to_string(),
                                                                mac.to_string()
                                                            ));
                                                        } else {
                                                            log::debug!("No NDP response for {}", ip);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        log::debug!("NDP failed for {}: {:?}", ip, e);
                                                    }
                                                }
                                            } else {
                                                log::debug!("No IPv6 address found on interface for NDP");
                                            }
                                        }
                                    }

                                    tx.try_send(Action::CountIp).unwrap_or_default();
                                };
                                tokio::spawn(c())
                            })
                            .collect();
                        for t in tasks {
                            match t.await {
                                Ok(_) => {}
                                Err(e) if e.is_cancelled() => {
                                    log::debug!("Discovery scan task was cancelled for IPv6 CIDR range");
                                }
                                Err(e) if e.is_panic() => {
                                    log::error!(
                                        "Discovery scan task panicked while scanning IPv6 CIDR range: {:?}",
                                        e
                                    );
                                }
                                Err(e) => {
                                    log::error!(
                                        "Discovery scan task failed while scanning IPv6 CIDR range: {:?}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                }

                log::debug!("CIDR scan task completed");
            });
        };
    }

    fn process_mac(&mut self, arp_data: ArpPacketData) {
        if let Some(n) = self
            .scanned_ips
            .iter_mut()
            .find(|item| item.ip == arp_data.sender_ip.to_string())
        {
            n.mac = arp_data.sender_mac.to_string();

            if let Some(oui) = &self.oui {
                let oui_res = oui.lookup_by_mac(&n.mac);
                if let Ok(Some(oui_res)) = oui_res {
                    let cn = oui_res.company_name.clone();
                    n.vendor = cn;
                }
            }
        }
    }

    fn process_ip(&mut self, ip: &str) {
        let Ok(hip) = ip.parse::<IpAddr>() else {
            return;
        };

        if let Some(n) = self.scanned_ips.iter_mut().find(|item| item.ip == ip) {
            n.ip = ip.to_string();
            n.ip_addr = hip;
        } else {
            let new_ip = ScannedIp {
                ip: ip.to_string(),
                ip_addr: hip,
                mac: String::new(),
                hostname: String::new(),
                vendor: String::new(),
            };

            let insert_pos = self.scanned_ips
                .binary_search_by(|probe| {
                    match (probe.ip_addr, hip) {
                        (IpAddr::V4(a), IpAddr::V4(b)) => a.cmp(&b),
                        (IpAddr::V6(a), IpAddr::V6(b)) => a.cmp(&b),
                        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
                        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
                    }
                })
                .unwrap_or_else(|pos| pos);
            self.scanned_ips.insert(insert_pos, new_ip);
        }

        self.set_scrollbar_height();

        if let Some(tx) = self.action_tx.clone() {
            let dns_cache = self.dns_cache.clone();
            let ip_string = ip.to_string();
            tokio::spawn(async move {
                let hostname = dns_cache.lookup_with_timeout(hip).await;
                if !hostname.is_empty() {
                    let _ = tx.try_send(Action::DnsResolved(ip_string, hostname));
                }
            });
        }
    }

    fn set_active_subnet(&mut self, interface: &NetworkInterface) {
        let a_ip = interface.ips[0].ip();

        match a_ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let new_a_ip = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                self.input = Input::default().with_value(new_a_ip);
                self.set_cidr(self.input.value().to_string(), false);
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    let new_a_ip = format!("fe80::{:x}:{:x}:{:x}:0/120",
                        segments[4], segments[5], segments[6]);
                    self.input = Input::default().with_value(new_a_ip);
                } else {
                    let new_a_ip = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:0/120",
                        segments[0], segments[1], segments[2], segments[3],
                        segments[4], segments[5], segments[6]);
                    self.input = Input::default().with_value(new_a_ip);
                }
                self.set_cidr(self.input.value().to_string(), false);
            }
        }
    }

    fn set_scrollbar_height(&mut self) {
        let mut ip_len = 0;
        if !self.scanned_ips.is_empty() {
            ip_len = self.scanned_ips.len() - 1;
        }
        self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    fn previous_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                if index == 0 {
                    if self.scanned_ips.is_empty() {
                        0
                    } else {
                        self.scanned_ips.len() - 1
                    }
                } else {
                    index - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                let mut s_ip_len = 0;
                if !self.scanned_ips.is_empty() {
                    s_ip_len = self.scanned_ips.len() - 1;
                }
                if index >= s_ip_len {
                    0
                } else {
                    index + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn make_table(
        scanned_ips: &Vec<ScannedIp>,
        cidr: Option<IpNetwork>,
        ip_num: i32,
        is_scanning: bool,
    ) -> Table<'_> {
        let header = Row::new(vec!["ip", "mac", "hostname", "vendor"])
            .style(Style::default().fg(Color::Yellow))
            .top_margin(1)
            .bottom_margin(1);
        let mut rows = Vec::new();
        let cidr_length = match cidr {
            Some(IpNetwork::V4(c)) => count_ipv4_net_length(c.prefix() as u32) as u64,
            Some(IpNetwork::V6(c)) => count_ipv6_net_length(c.prefix() as u32),
            None => 0,
        };

        for sip in scanned_ips {
            let ip = &sip.ip;
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    format!("{ip:<2}"),
                    Style::default().fg(Color::Blue),
                )),
                Cell::from(sip.mac.as_str().green()),
                Cell::from(sip.hostname.as_str()),
                Cell::from(sip.vendor.as_str().yellow()),
            ]));
        }

        let mut scan_title = vec![
            Span::styled("|", Style::default().fg(Color::Yellow)),
            "◉ ".green(),
            Span::styled(
                format!("{}", scanned_ips.len()),
                Style::default().fg(Color::Red),
            ),
            Span::styled("|", Style::default().fg(Color::Yellow)),
        ];
        if is_scanning {
            scan_title.push(" ⣿(".yellow());
            scan_title.push(format!("{}", ip_num).red());
            scan_title.push(format!("/{}", cidr_length).green());
            scan_title.push(")".yellow());
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(40),
                Constraint::Length(19),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ],
        )
        .header(header)
        .block(
            Block::new()
                .title(
                    ratatui::widgets::block::Title::from("|Discovery|".yellow())
                        .position(ratatui::widgets::block::Position::Top)
                        .alignment(Alignment::Right),
                )
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        Span::styled(
                            "e",
                            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                        ),
                        Span::styled("xport data", Style::default().fg(Color::Yellow)),
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                    ]))
                    .alignment(Alignment::Left)
                    .position(ratatui::widgets::block::Position::Bottom),
                )
                .title(
                    ratatui::widgets::block::Title::from(Line::from(scan_title))
                        .position(ratatui::widgets::block::Position::Top)
                        .alignment(Alignment::Left),
                )
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        String::from(char::from_u32(0x25b2).unwrap_or('>')).red(),
                        String::from(char::from_u32(0x25bc).unwrap_or('>')).red(),
                        Span::styled("select|", Style::default().fg(Color::Yellow)),
                    ]))
                    .position(ratatui::widgets::block::Position::Bottom)
                    .alignment(Alignment::Right),
                )
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .borders(Borders::ALL)
                .border_type(DEFAULT_BORDER_STYLE),
        )
        .highlight_symbol(String::from(char::from_u32(0x25b6).unwrap_or('>')).red())
        .column_spacing(1);
        table
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None);
        scrollbar
    }

    fn make_input(&self, scroll: usize) -> Paragraph<'_> {
        let input = Paragraph::new(self.input.value())
            .style(Style::default().fg(Color::Green))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(match self.mode {
                        Mode::Input => Style::default().fg(Color::Green),
                        Mode::Normal => Style::default().fg(Color::Rgb(100, 100, 100)),
                    })
                    .border_type(DEFAULT_BORDER_STYLE)
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "i",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("nput", Style::default().fg(Color::Yellow)),
                            Span::raw("/"),
                            Span::styled(
                                "ESC",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Right)
                        .position(ratatui::widgets::block::Position::Bottom),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Left)
                        .position(ratatui::widgets::block::Position::Bottom),
                    ),
            );
        input
    }

    fn make_error(&mut self) -> Paragraph<'_> {
        let error = Paragraph::new("CIDR parse error")
            .style(Style::default().fg(Color::Red))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(Color::Red)),
            );
        error
    }

    fn make_spinner(&self) -> Span<'_> {
        let spinner = SPINNER_SYMBOLS[self.spinner_index];
        Span::styled(
            format!("{spinner}scanning.."),
            Style::default().fg(Color::Yellow),
        )
    }
}

impl Component for Discovery {
    fn init(&mut self, _area: Size) -> Result<()> {
        if self.cidr.is_none() {
            self.set_cidr(String::from(DEFAULT_IP), false);
        }
        match Oui::default() {
            Ok(s) => self.oui = Some(s),
            Err(_) => self.oui = None,
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, action_tx: Sender<Action>) -> Result<()> {
        self.action_tx = Some(action_tx);
        Ok(())
    }

    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        if self.active_tab == TabsEnum::Discovery {
            let action = match self.mode {
                Mode::Normal => return Ok(None),
                Mode::Input => match key.code {
                    KeyCode::Enter => {
                        if let Some(_sender) = &self.action_tx {
                            self.set_cidr(self.input.value().to_string(), true);
                        }
                        Action::ModeChange(Mode::Normal)
                    }
                    _ => {
                        self.input.handle_event(&Event::Key(key));
                        return Ok(None);
                    }
                },
            };
            Ok(Some(action))
        } else {
            Ok(None)
        }
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if self.is_scanning && self.task.is_finished() {
            log::warn!("Scan task finished unexpectedly, checking for errors");
            self.is_scanning = false;
        }

        if self.is_scanning {
            if let Action::Tick = action {
                let mut s_index = self.spinner_index + 1;
                s_index %= SPINNER_SYMBOLS.len();
                self.spinner_index = s_index;
            }
        }

        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
        }
        if let Action::DnsResolved(ref ip, ref hostname) = action {
            if let Some(entry) = self.scanned_ips.iter_mut().find(|item| item.ip == *ip) {
                entry.hostname = hostname.clone();
            }
        }
        if let Action::UpdateMac(ref ip, ref mac) = action {
            if let Some(entry) = self.scanned_ips.iter_mut().find(|item| item.ip == *ip) {
                entry.mac = mac.clone();
                if let Some(oui) = &self.oui {
                    if let Ok(Some(oui_res)) = oui.lookup_by_mac(mac) {
                        entry.vendor = oui_res.company_name.clone();
                    }
                }
            }
        }
        if let Action::CountIp = action {
            self.ip_num += 1;

            let ip_count = match self.cidr {
                Some(IpNetwork::V4(cidr)) => count_ipv4_net_length(cidr.prefix() as u32) as i32,
                Some(IpNetwork::V6(cidr)) => {
                    let count = count_ipv6_net_length(cidr.prefix() as u32);
                    if count > i32::MAX as u64 {
                        i32::MAX
                    } else {
                        count as i32
                    }
                }
                None => 0,
            };

            if self.ip_num == ip_count {
                self.is_scanning = false;
            }
        }
        if let Action::CidrError = action {
            self.cidr_error = true;
        }
        if let Action::ArpRecieve(ref arp_data) = action {
            self.process_mac(arp_data.clone());
        }
        if let Action::ScanCidr = action {
            if self.active_interface.is_some()
                && !self.is_scanning
                && self.active_tab == TabsEnum::Discovery
            {
                self.scan();
            }
        }
        if let Action::ActiveInterface(ref interface) = action {
            if self.active_interface.is_none() {
                self.set_active_subnet(interface);
            }
            self.active_interface = Some(interface.clone());
        }

        if self.active_tab == TabsEnum::Discovery {
            if let Action::Down = action {
                self.next_in_table();
            }
            if let Action::Up = action {
                self.previous_in_table();
            }

            if let Action::ModeChange(mode) = action {
                if self.is_scanning && mode == Mode::Input {
                    if let Some(tx) = &self.action_tx {
                        let _ = tx.clone().try_send(Action::ModeChange(Mode::Normal));
                    }
                    return Ok(None);
                }

                if mode == Mode::Input {
                    self.cidr_error = false;
                }
                if let Some(tx) = &self.action_tx {
                    let _ = tx.clone().try_send(Action::AppModeChange(mode));
                }
                self.mode = mode;
            }
        }

        if let Action::TabChange(tab) = action {
            let _ = self.tab_changed(tab);
        }

        Ok(None)
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        log::info!("Shutting down discovery component");
        self.is_scanning = false;
        self.task.abort();
        log::info!("Discovery component shutdown complete");
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Discovery {
            let layout = get_vertical_layout(area);

            let mut table_rect = layout.bottom;
            table_rect.y += 1;
            table_rect.height -= 1;

            let table =
                Self::make_table(&self.scanned_ips, self.cidr, self.ip_num, self.is_scanning);
            f.render_stateful_widget(table, table_rect, &mut self.table_state);

            let scrollbar = Self::make_scrollbar();
            let mut scroll_rect = table_rect;
            scroll_rect.y += 3;
            scroll_rect.height -= 3;
            f.render_stateful_widget(
                scrollbar,
                scroll_rect.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                &mut self.scrollbar_state,
            );

            if self.cidr_error {
                let error_rect = Rect::new(table_rect.width - (19 + 41), table_rect.y + 1, 18, 3);
                let block = self.make_error();
                f.render_widget(block, error_rect);
            }

            let input_size: u16 = INPUT_SIZE as u16;
            let input_rect = Rect::new(
                table_rect.width - (input_size + 1),
                table_rect.y + 1,
                input_size,
                3,
            );

            let scroll = self.input.visual_scroll(INPUT_SIZE - 3);
            let mut block = self.make_input(scroll);
            if self.is_scanning {
                block = block.add_modifier(Modifier::DIM);
            }
            f.render_widget(block, input_rect);

            match self.mode {
                Mode::Input => {
                    f.set_cursor_position(Position {
                        x: input_rect.x
                            + ((self.input.visual_cursor()).max(scroll) - scroll) as u16
                            + 1,
                        y: input_rect.y + 1,
                    });
                }
                Mode::Normal => {}
            }

            if self.is_scanning {
                let throbber = self.make_spinner();
                let throbber_rect = Rect::new(input_rect.x + 1, input_rect.y, 12, 1);
                f.render_widget(throbber, throbber_rect);
            }
        }

        Ok(())
    }
}

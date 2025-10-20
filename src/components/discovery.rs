use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use ipnetwork::IpNetwork;

use pnet::datalink::NetworkInterface;
use tokio::sync::Semaphore;

use core::str;
use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::net::IpAddr;
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

// Default concurrent ping scan pool size
// Used as fallback if CPU detection fails or for single-core systems
const _DEFAULT_POOL_SIZE: usize = 32;

// Minimum concurrent operations to maintain reasonable performance
const MIN_POOL_SIZE: usize = 16;

// Maximum concurrent operations to prevent resource exhaustion
const MAX_POOL_SIZE: usize = 64;

// Ping timeout in seconds
// Time to wait for ICMP echo reply before considering host unreachable
// 2 seconds provides good balance between speed and reliability for local networks
const PING_TIMEOUT_SECS: u64 = 2;

// Width of the CIDR input field in characters
const INPUT_SIZE: usize = 30;

// Default CIDR range for initial scan (IPv4)
const DEFAULT_IP: &str = "192.168.1.0/24";

// Animation frames for the scanning spinner
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Clone, Debug, PartialEq)]
pub struct ScannedIp {
    pub ip: String,
    pub ip_addr: IpAddr, // Cached parsed IP for efficient sorting (both IPv4 and IPv6)
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
    cidr: Option<IpNetwork>, // Support both IPv4 and IPv6 CIDR
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

    // Calculate optimal pool size based on available CPU cores
    // Returns a value between MIN_POOL_SIZE and MAX_POOL_SIZE
    fn get_pool_size() -> usize {
        // Try to detect number of CPU cores
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4); // Default to 4 if detection fails

        // Use 2x CPU cores as starting point for I/O-bound operations
        let calculated = num_cpus * 2;

        // Clamp to min/max bounds
        calculated.clamp(MIN_POOL_SIZE, MAX_POOL_SIZE)
    }

    pub fn get_scanned_ips(&self) -> &Vec<ScannedIp> {
        &self.scanned_ips
    }

    fn set_cidr(&mut self, cidr_str: String, scan: bool) {
        // Validate input is not empty and doesn't contain suspicious characters
        let trimmed = cidr_str.trim();
        if trimmed.is_empty() {
            if let Some(tx) = &self.action_tx {
                let _ = tx.clone().try_send(Action::CidrError);
            }
            return;
        }

        // Basic format validation before parsing
        if !trimmed.contains('/') {
            if let Some(tx) = &self.action_tx {
                let _ = tx.clone().try_send(Action::CidrError);
            }
            return;
        }

        // Try parsing as IpNetwork (supports both IPv4 and IPv6)
        match trimmed.parse::<IpNetwork>() {
            Ok(ip_network) => {
                match ip_network {
                    IpNetwork::V4(ipv4_net) => {
                        // IPv4 validation
                        let network_length = ipv4_net.prefix();

                        if network_length < 16 {
                            // Network too large - prevent scanning millions of IPs
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }

                        // Validate it's not a special-purpose network
                        let first_octet = ipv4_net.network().octets()[0];

                        // Reject loopback (127.0.0.0/8), multicast (224.0.0.0/4), and reserved ranges
                        if first_octet == 127 || first_octet >= 224 {
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }
                    }
                    IpNetwork::V6(ipv6_net) => {
                        // IPv6 validation
                        let network_length = ipv6_net.prefix();

                        // For IPv6, enforce minimum /120 to prevent scanning massive ranges
                        // /120 = 256 addresses, which is reasonable
                        if network_length < 120 {
                            log::warn!("IPv6 network /{} is too large for scanning, minimum is /120", network_length);
                            if let Some(tx) = &self.action_tx {
                                let _ = tx.clone().try_send(Action::CidrError);
                            }
                            return;
                        }

                        // Validate it's not a special-purpose network
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

            // Early return if action_tx is not available
            // Clone necessary: Sender will be moved into async task
            let Some(tx) = self.action_tx.clone() else {
                self.is_scanning = false;
                return;
            };

            // Calculate optimal pool size based on system resources
            let pool_size = Self::get_pool_size();
            log::debug!("Using pool size of {} for discovery scan", pool_size);
            let semaphore = Arc::new(Semaphore::new(pool_size));

            self.task = tokio::spawn(async move {
                log::debug!("Starting CIDR scan task for {:?}", cidr);

                match cidr {
                    IpNetwork::V4(ipv4_cidr) => {
                        // Convert ipnetwork::Ipv4Network to cidr::Ipv4Cidr
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
                                    // Semaphore acquire should not fail in normal operation
                                    // If it does, we skip this IP and continue
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
                            // Check if task panicked or was aborted
                            match t.await {
                                Ok(_) => {
                                    // Task completed successfully
                                }
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
                        // IPv6 scanning
                        let ips = get_ips6_from_cidr(ipv6_cidr);
                        log::debug!("Scanning {} IPv6 addresses", ips.len());

                        let tasks: Vec<_> = ips
                            .iter()
                            .map(|&ip| {
                                let s = semaphore.clone();
                                let tx = tx.clone();
                                let c = || async move {
                                    // Semaphore acquire should not fail in normal operation
                                    // If it does, we skip this IP and continue
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
                                        .pinger(IpAddr::V6(ip), PingIdentifier(random()))
                                        .await;
                                    pinger.timeout(Duration::from_secs(PING_TIMEOUT_SECS));

                                    match pinger.ping(PingSequence(2), &payload).await {
                                        Ok((IcmpPacket::V6(_packet), _dur)) => {
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
                            // Check if task panicked or was aborted
                            match t.await {
                                Ok(_) => {
                                    // Task completed successfully
                                }
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
        // Parse IP address - should always succeed as it comes from successful ping
        let Ok(hip) = ip.parse::<IpAddr>() else {
            // If parsing fails, skip this IP
            return;
        };

        // Add IP immediately without hostname (will be updated asynchronously)
        if let Some(n) = self.scanned_ips.iter_mut().find(|item| item.ip == ip) {
            n.ip = ip.to_string();
            n.ip_addr = hip;
        } else {
            let new_ip = ScannedIp {
                ip: ip.to_string(),
                ip_addr: hip,
                mac: String::new(),
                hostname: String::new(), // Will be filled asynchronously
                vendor: String::new(),
            };

            // Use binary search to find the correct insertion position
            // This maintains sorted order in O(n) time instead of O(n log n) for full sort
            let insert_pos = self.scanned_ips
                .binary_search_by(|probe| {
                    // Compare IpAddr directly - supports both IPv4 and IPv6
                    match (probe.ip_addr, hip) {
                        (IpAddr::V4(a), IpAddr::V4(b)) => a.cmp(&b),
                        (IpAddr::V6(a), IpAddr::V6(b)) => a.cmp(&b),
                        // IPv4 addresses sort before IPv6 addresses
                        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
                        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
                    }
                })
                .unwrap_or_else(|pos| pos);
            self.scanned_ips.insert(insert_pos, new_ip);
        }

        self.set_scrollbar_height();

        // Perform DNS lookup asynchronously in background
        // Clone necessary: Values moved into async task
        if let Some(tx) = self.action_tx.clone() {
            let dns_cache = self.dns_cache.clone(); // Arc clone - cheap
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
                // IPv4 subnet detection
                let octets = ipv4.octets();
                let new_a_ip = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                self.input = Input::default().with_value(new_a_ip);
                self.set_cidr(self.input.value().to_string(), false);
            }
            IpAddr::V6(ipv6) => {
                // IPv6 subnet detection - use /120 for reasonable scanning
                // Get the network portion (first 120 bits)
                let segments = ipv6.segments();
                // For link-local addresses (fe80::/10), use the common /64 prefix
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    let new_a_ip = format!("fe80::{:x}:{:x}:{:x}:0/120",
                        segments[4], segments[5], segments[6]);
                    self.input = Input::default().with_value(new_a_ip);
                } else {
                    // For other IPv6 addresses, construct a /120 subnet
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
                Constraint::Length(40), // Increased for IPv6 addresses (up to 39 chars)
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
        // -- init oui
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
        // Monitor task health
        if self.is_scanning && self.task.is_finished() {
            // Task finished unexpectedly while still marked as scanning
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

        // -- custom actions
        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
        }
        // -- DNS resolved
        if let Action::DnsResolved(ref ip, ref hostname) = action {
            if let Some(entry) = self.scanned_ips.iter_mut().find(|item| item.ip == *ip) {
                entry.hostname = hostname.clone();
            }
        }
        // -- count IPs
        if let Action::CountIp = action {
            self.ip_num += 1;

            let ip_count = match self.cidr {
                Some(IpNetwork::V4(cidr)) => count_ipv4_net_length(cidr.prefix() as u32) as i32,
                Some(IpNetwork::V6(cidr)) => {
                    let count = count_ipv6_net_length(cidr.prefix() as u32);
                    // Cap at i32::MAX for practical purposes
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
        // -- CIDR error
        if let Action::CidrError = action {
            self.cidr_error = true;
        }
        // -- ARP packet recieved
        if let Action::ArpRecieve(ref arp_data) = action {
            self.process_mac(arp_data.clone());
        }
        // -- Scan CIDR
        if let Action::ScanCidr = action {
            if self.active_interface.is_some()
                && !self.is_scanning
                && self.active_tab == TabsEnum::Discovery
            {
                self.scan();
            }
        }
        // -- active interface
        if let Action::ActiveInterface(ref interface) = action {
            // -- first time scan after setting of interface
            if self.active_interface.is_none() {
                self.set_active_subnet(interface);
            }
            self.active_interface = Some(interface.clone());
        }

        if self.active_tab == TabsEnum::Discovery {
            // -- prev & next select item in table
            if let Action::Down = action {
                self.next_in_table();
            }
            if let Action::Up = action {
                self.previous_in_table();
            }

            // -- MODE CHANGE
            if let Action::ModeChange(mode) = action {
                // -- when scanning don't switch to input mode
                if self.is_scanning && mode == Mode::Input {
                    if let Some(tx) = &self.action_tx {
                        let _ = tx.clone().try_send(Action::ModeChange(Mode::Normal));
                    }
                    return Ok(None);
                }

                if mode == Mode::Input {
                    // self.input.reset();
                    self.cidr_error = false;
                }
                if let Some(tx) = &self.action_tx {
                    let _ = tx.clone().try_send(Action::AppModeChange(mode));
                }
                self.mode = mode;
            }
        }

        // -- tab change
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

        // Mark as not scanning to stop any ongoing operations
        self.is_scanning = false;

        // Abort the scanning task if it's still running
        self.task.abort();

        log::info!("Discovery component shutdown complete");
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Discovery {
            let layout = get_vertical_layout(area);

            // -- TABLE
            let mut table_rect = layout.bottom;
            table_rect.y += 1;
            table_rect.height -= 1;

            let table =
                Self::make_table(&self.scanned_ips, self.cidr, self.ip_num, self.is_scanning);
            f.render_stateful_widget(table, table_rect, &mut self.table_state);

            // -- SCROLLBAR
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

            // -- ERROR
            if self.cidr_error {
                let error_rect = Rect::new(table_rect.width - (19 + 41), table_rect.y + 1, 18, 3);
                let block = self.make_error();
                f.render_widget(block, error_rect);
            }

            // -- INPUT
            let input_size: u16 = INPUT_SIZE as u16;
            let input_rect = Rect::new(
                table_rect.width - (input_size + 1),
                table_rect.y + 1,
                input_size,
                3,
            );

            // -- INPUT_SIZE - 3 is offset for border + 1char for cursor
            let scroll = self.input.visual_scroll(INPUT_SIZE - 3);
            let mut block = self.make_input(scroll);
            if self.is_scanning {
                block = block.add_modifier(Modifier::DIM);
            }
            f.render_widget(block, input_rect);

            // -- cursor
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

            // -- THROBBER
            if self.is_scanning {
                let throbber = self.make_spinner();
                let throbber_rect = Rect::new(input_rect.x + 1, input_rect.y, 12, 1);
                f.render_widget(throbber, throbber_rect);
            }
        }

        Ok(())
    }
}

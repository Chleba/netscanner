use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};
use futures::future::join_all;

use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    MutablePacket, Packet,
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
};
use pnet::util::MacAddr;
use tokio::sync::Semaphore;

use core::str;
use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::string;
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::Component;
use crate::{
    action::Action,
    components::packetdump::ArpPacketData,
    config::DEFAULT_BORDER_STYLE,
    enums::TabsEnum,
    layout::get_vertical_layout,
    mode::Mode,
    tui::Frame,
    utils::{count_ipv4_net_length, get_ips4_from_cidr},
};
use mac_oui::Oui;
use rand::random;

/// Extension trait to load OUI database from a CSV string (for embedded/fresh DB)
pub trait OuiExt {
    fn from_csv_str(csv_text: &str) -> Result<Oui, String>;
}

impl OuiExt for Oui {
    fn from_csv_str(csv_text: &str) -> Result<Oui, String> {
        // Write CSV to temp file and load via from_csv_file
        let tmp_path = format!("/tmp/netscanner_oui_{}.csv", std::process::id());
        std::fs::write(&tmp_path, csv_text).map_err(|e| e.to_string())?;
        let result = Self::from_csv_file(&tmp_path);
        let _ = std::fs::remove_file(&tmp_path);
        result
    }
}
use ratatui::crossterm::event::Event;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler;

static POOL_SIZE: usize = 32;
static INPUT_SIZE: usize = 30;
static DEFAULT_IP: &str = "192.168.1.0/24";
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Clone, Debug, PartialEq)]
pub struct ScannedIp {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
}

pub struct Discovery {
    active_tab: TabsEnum,
    active_interface: Option<NetworkInterface>,
    action_tx: Option<UnboundedSender<Action>>,
    scanned_ips: Vec<ScannedIp>,
    ip_num: i32,
    input: Input,
    cidr: Option<Ipv4Cidr>,
    cidr_error: bool,
    is_scanning: bool,
    mode: Mode,
    task: JoinHandle<()>,
    oui: Option<Oui>,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
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
            table_state: {
                let mut state = TableState::default();
                state.select(Some(0));
                state
            },
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
        }
    }

    pub fn get_scanned_ips(&self) -> &Vec<ScannedIp> {
        &self.scanned_ips
    }

    fn set_cidr(&mut self, cidr_str: String, scan: bool) {
        match cidr_str.parse::<Ipv4Cidr>() {
            Ok(ip_cidr) => {
                self.cidr = Some(ip_cidr);
                if scan {
                    self.scan();
                }
            }
            Err(e) => {
                if let Some(tx) = &self.action_tx {
                    tx.clone().send(Action::CidrError).unwrap();
                }
            }
        }
    }

    fn reset_scan(&mut self) {
        self.scanned_ips.clear();
        self.ip_num = 0;
    }

    fn send_arp(&mut self, target_ip: Ipv4Addr) {
        if let Some(active_interface) = &self.active_interface {
            if let Some(active_interface_mac) = active_interface.mac {
                let ipv4 = active_interface.ips.iter().find(|f| f.is_ipv4()).unwrap();
                let source_ip: Ipv4Addr = ipv4.ip().to_string().parse().unwrap();

                let (mut sender, _) =
                    match pnet::datalink::channel(active_interface, Default::default()) {
                        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                        Ok(_) => {
                            if let Some(tx_action) = &self.action_tx {
                                tx_action
                                    .clone()
                                    .send(Action::Error(
                                        "Unknown or unsupported channel type".into(),
                                    ))
                                    .unwrap();
                            }
                            return;
                        }
                        Err(e) => {
                            if let Some(tx_action) = &self.action_tx {
                                tx_action
                                    .clone()
                                    .send(Action::Error(format!(
                                        "Unable to create datalink channel: {e}"
                                    )))
                                    .unwrap();
                            }
                            return;
                        }
                    };

                let mut ethernet_buffer = [0u8; 42];
                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

                ethernet_packet.set_destination(MacAddr::broadcast());
                ethernet_packet.set_source(active_interface_mac);
                ethernet_packet.set_ethertype(EtherTypes::Arp);

                let mut arp_buffer = [0u8; 28];
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Request);
                arp_packet.set_sender_hw_addr(active_interface_mac);
                arp_packet.set_sender_proto_addr(source_ip);
                arp_packet.set_target_hw_addr(MacAddr::zero());
                arp_packet.set_target_proto_addr(target_ip);

                ethernet_packet.set_payload(arp_packet.packet_mut());

                sender
                    .send_to(ethernet_packet.packet(), None)
                    .unwrap()
                    .unwrap();
            }
        }
    }

    // fn scan(&mut self) {
    //     self.reset_scan();

    //     if let Some(cidr) = self.cidr {
    //         self.is_scanning = true;
    //         let tx = self.action_tx.as_ref().unwrap().clone();
    //         self.task = tokio::spawn(async move {
    //             let ips = get_ips4_from_cidr(cidr);
    //             let chunks: Vec<_> = ips.chunks(POOL_SIZE).collect();
    //             for chunk in chunks {
    //                 let tasks: Vec<_> = chunk
    //                     .iter()
    //                     .map(|&ip| {
    //                         let tx = tx.clone();
    //                         let closure = || async move {
    //                             let client =
    //                                 Client::new(&Config::default()).expect("Cannot create client");
    //                             let payload = [0; 56];
    //                             let mut pinger = client
    //                                 .pinger(IpAddr::V4(ip), PingIdentifier(random()))
    //                                 .await;
    //                             pinger.timeout(Duration::from_secs(2));

    //                             match pinger.ping(PingSequence(2), &payload).await {
    //                                 Ok((IcmpPacket::V4(packet), dur)) => {
    //                                     tx.send(Action::PingIp(packet.get_real_dest().to_string()))
    //                                         .unwrap_or_default();
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                                 Ok(_) => {
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                                 Err(_) => {
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                             }
    //                         };
    //                         task::spawn(closure())
    //                     })
    //                     .collect();

    //                 let _ = join_all(tasks).await;
    //             }
    //         });
    //     };
    // }

    fn scan(&mut self) {
        self.reset_scan();

        if let Some(cidr) = self.cidr {
            self.is_scanning = true;

            let tx = self.action_tx.clone().unwrap();
            let semaphore = Arc::new(Semaphore::new(POOL_SIZE));

            self.task = tokio::spawn(async move {
                let ips = get_ips4_from_cidr(cidr);
                let tasks: Vec<_> = ips
                    .iter()
                    .map(|&ip| {
                        let s = semaphore.clone();
                        let tx = tx.clone();
                        let c = || async move {
                            let _permit = s.acquire().await.unwrap();
                            let client =
                                Client::new(&Config::default()).expect("Cannot create client");
                            let payload = [0; 56];
                            let mut pinger = client
                                .pinger(IpAddr::V4(ip), PingIdentifier(random()))
                                .await;
                            pinger.timeout(Duration::from_secs(2));

                            match pinger.ping(PingSequence(2), &payload).await {
                                Ok((IcmpPacket::V4(packet), dur)) => {
                                    tx.send(Action::PingIp(packet.get_real_dest().to_string()))
                                        .unwrap_or_default();
                                    tx.send(Action::CountIp).unwrap_or_default();
                                }
                                Ok(_) => {
                                    tx.send(Action::CountIp).unwrap_or_default();
                                }
                                Err(_) => {
                                    tx.send(Action::CountIp).unwrap_or_default();
                                }
                            }
                        };
                        tokio::spawn(c())
                    })
                    .collect();
                for t in tasks {
                    let _ = t.await;
                }
                // let _ = join_all(tasks).await;
            });
        };
    }

    fn process_mac(&mut self, arp_data: ArpPacketData) {
        // Only accept ARP responses (not requests)
        if arp_data.operation == pnet::packet::arp::ArpOperations::Reply {
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
    }

    /// Try to get MAC from the system's ARP cache (/proc/net/arp on Linux)
    fn try_arp_cache(&mut self) {
        let content = match fs::read_to_string("/proc/net/arp") {
            Ok(c) => c,
            Err(_) => return, // Not on Linux or no access
        };

        for line in content.lines().skip(1) { // skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            // Format: IP address HW type Flags HW address Mask Device
            let ip_str = parts[0];
            let hw_addr_str = parts[3];

            // Check if this is a known scanned IP
            if let Some(n) = self
                .scanned_ips
                .iter_mut()
                .find(|item| item.ip == ip_str)
            {
                // Only use if we don't have a MAC yet, or it's currently empty
                if n.mac.is_empty() {
                    n.mac = hw_addr_str.to_string();

                    if let Some(oui) = &self.oui {
                        let oui_res = oui.lookup_by_mac(&n.mac);
                        if let Ok(Some(oui_res)) = oui_res {
                            let cn = oui_res.company_name.clone();
                            n.vendor = cn;
                        }
                    }
                }
            }
        }
    }

    /// Send ARP request for a specific IP and schedule retries if no response
    fn send_arp_with_retry(&mut self, ip: &str) {
        let ipv4: Ipv4Addr = ip.parse().unwrap();
        self.send_arp(ipv4);

        // Schedule retries at 1s, 2s, 3s if no ARP response received
        let ip_clone = ip.to_string();
        let tx = self.action_tx.clone();

        for delay_secs in [1u64, 2, 3] {
            let tx = tx.clone();
            let ip = ip_clone.clone();
            let delay = Duration::from_secs(delay_secs);

            let tx_inner = tx.clone().unwrap();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = tx_inner.send(Action::ArpRetry(ip));
            });
        }
    }

    fn process_hostname_retry(&self, ip: String) {
        let tx = self.action_tx.as_ref().unwrap().clone();

        // Spawn a delayed retry task for reverse DNS lookup
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let hip: IpAddr = ip.parse().unwrap();
            let host = lookup_addr(&hip).unwrap_or_default();
            if !host.is_empty() {
                let _ = tx.send(Action::HostnameUpdate(ip, host));
            }
        });
    }

    fn process_ip(&mut self, ip: &str) {
        let tx = self.action_tx.as_ref().unwrap();
        let ipv4: Ipv4Addr = ip.parse().unwrap();
        // Send ARP request to get MAC address
        self.send_arp_with_retry(ip);

        let hip: IpAddr = ip.parse().unwrap();
        let host = lookup_addr(&hip).unwrap_or_default();
        let needs_retry = host.is_empty();

        if let Some(n) = self.scanned_ips.iter_mut().find(|item| item.ip == ip) {
            n.hostname = host.clone();
            n.ip = ip.to_string();
        } else {
            self.scanned_ips.push(ScannedIp {
                ip: ip.to_string(),
                mac: String::new(),
                hostname: host.clone(),
                vendor: String::new(),
            });

            self.scanned_ips.sort_by(|a, b| {
                let a_ip: Ipv4Addr = a.ip.parse::<Ipv4Addr>().unwrap();
                let b_ip: Ipv4Addr = b.ip.parse::<Ipv4Addr>().unwrap();
                a_ip.partial_cmp(&b_ip).unwrap()
            });
        }

        // Schedule retry after mutable borrow is done
        if needs_retry {
            self.process_hostname_retry(ip.to_string());
        }

        self.set_scrollbar_height();
    }

    fn set_active_subnet(&mut self, intf: &NetworkInterface) {
        let ipv4 = intf.ips.iter().find(|ip| ip.is_ipv4());
        if let Some(ip_network) = ipv4 {
            let cidr_str = format!("{}/{}", ip_network.network(), ip_network.prefix());
            self.input = Input::default().with_value(cidr_str.clone());
            self.set_cidr(cidr_str, false);
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
                if index >= s_ip_len { 0 } else { index + 1 }
            }
            None => 0,
        };
        self.table_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn make_table(
        scanned_ips: &Vec<ScannedIp>,
        cidr: Option<Ipv4Cidr>,
        ip_num: i32,
        is_scanning: bool,
    ) -> Table<'_> {
        let header = Row::new(vec!["ip", "mac", "hostname", "vendor"])
            .style(Style::default().fg(Color::Yellow))
            .top_margin(1)
            .bottom_margin(1);
        let mut rows = Vec::new();
        let cidr_length = match cidr {
            Some(c) => count_ipv4_net_length(c.network_length() as u32),
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
                Constraint::Length(16),
                Constraint::Length(19),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title_top(Line::from("|Discovery|").yellow().right_aligned())
                .title_bottom(
                    Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        Span::styled(
                            "e",
                            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                        ),
                        Span::styled("xport data", Style::default().fg(Color::Yellow)),
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                    ])
                    .left_aligned(),
                )
                .title_top(Line::from(scan_title).left_aligned())
                .title_bottom(
                    Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        String::from(char::from_u32(0x25b2).unwrap_or('>')).red(),
                        String::from(char::from_u32(0x25bc).unwrap_or('>')).red(),
                        Span::styled("select|", Style::default().fg(Color::Yellow)),
                    ])
                    .right_aligned(),
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
                    .title_bottom(
                        Line::from(vec![
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
                        ])
                        .right_aligned(),
                    )
                    .title_bottom(
                        Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ])
                        .left_aligned(),
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
    fn init(&mut self, area: Size) -> Result<()> {
        if self.cidr.is_none() {
            self.set_cidr(String::from(DEFAULT_IP), false);
        }
        // -- init oui with embedded fresh database
        let csv_data = include_str!("../../assets/oui.csv");
        match Oui::from_csv_str(csv_data) {
            Ok(s) => self.oui = Some(s),
            Err(_) => {
                // Fallback to default bundled DB if embedded fails
                match Oui::default() {
                    Ok(s) => self.oui = Some(s),
                    Err(_) => self.oui = None,
                }
            }
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        if self.active_tab == TabsEnum::Discovery {
            let action = match self.mode {
                Mode::Normal => return Ok(None),
                Mode::Input => match key.code {
                    KeyCode::Enter => {
                        if let Some(sender) = &self.action_tx {
                            self.set_cidr(self.input.value().to_string(), true);
                        }
                        Action::ModeChange(Mode::Normal)
                    }
                    _ => {
                        self.input
                            .handle_event(&ratatui::crossterm::event::Event::Key(key));
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
        if self.is_scanning {
            if let Action::Tick = action {
                let mut s_index = self.spinner_index + 1;
                s_index %= SPINNER_SYMBOLS.len() - 1;
                self.spinner_index = s_index;
            }
        }

        // -- custom actions
        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
        }
        // -- hostname retry update
        if let Action::HostnameUpdate(ref ip, ref host) = action {
            if let Some(n) = self.scanned_ips.iter_mut().find(|item| item.ip == *ip) {
                n.hostname = host.clone();
            }
        }
        // -- count IPs
        if let Action::CountIp = action {
            self.ip_num += 1;

            let ip_count = match self.cidr {
                Some(cidr) => count_ipv4_net_length(cidr.network_length() as u32) as i32,
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
        // -- ARP retry: send another ARP request + try /proc/net/arp
        if let Action::ArpRetry(ref ip) = action {
            // Send another ARP request
            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                self.send_arp(ipv4);
            }
            // Try reading from kernel ARP cache as fallback
            self.try_arp_cache();
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
            let intf = interface.clone();
            // -- update subnet input and clear old scan results when switching interfaces
            self.set_active_subnet(&intf);
            self.reset_scan();
            self.active_interface = Some(intf);
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
                    self.action_tx
                        .clone()
                        .unwrap()
                        .send(Action::ModeChange(Mode::Normal))
                        .unwrap();
                    return Ok(None);
                }

                if mode == Mode::Input {
                    // self.input.reset();
                    self.cidr_error = false;
                }
                self.action_tx
                    .clone()
                    .unwrap()
                    .send(Action::AppModeChange(mode))
                    .unwrap();
                self.mode = mode;
            }
        }

        // -- tab change
        if let Action::TabChange(tab) = action {
            self.tab_changed(tab).unwrap();
        }

        Ok(None)
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
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

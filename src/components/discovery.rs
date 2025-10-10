use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;

use pnet::datalink::NetworkInterface;
use tokio::sync::Semaphore;

use core::str;
use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr};
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
    utils::{count_ipv4_net_length, get_ips4_from_cidr},
};
use crossterm::event::Event;
use crossterm::event::{KeyCode, KeyEvent};
use mac_oui::Oui;
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

// Concurrent ping scan pool size
// Limits the number of concurrent ping operations to avoid overwhelming the network
// or exhausting system resources. 32 provides good throughput while remaining conservative.
const POOL_SIZE: usize = 32;

// Width of the CIDR input field in characters
const INPUT_SIZE: usize = 30;

// Default CIDR range for initial scan
const DEFAULT_IP: &str = "192.168.1.0/24";

// Animation frames for the scanning spinner
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Clone, Debug, PartialEq)]
pub struct ScannedIp {
    pub ip: String,
    pub ip_addr: Ipv4Addr, // Cached parsed IP for efficient sorting
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
    cidr: Option<Ipv4Cidr>,
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

        match trimmed.parse::<Ipv4Cidr>() {
            Ok(ip_cidr) => {
                // Validate CIDR range is reasonable (prevent scanning entire internet)
                // Minimum network length /8 (16,777,216 hosts) - too large
                // Maximum network length /32 (1 host) - pointless but allowed
                // Recommended minimum: /16 (65,536 hosts)
                // For safety, we'll enforce a minimum of /16
                let network_length = ip_cidr.network_length();

                if network_length < 16 {
                    // Network too large - prevent scanning millions of IPs
                    if let Some(tx) = &self.action_tx {
                        let _ = tx.clone().try_send(Action::CidrError);
                    }
                    return;
                }

                // Validate it's not a special-purpose network
                let first_octet = ip_cidr.first_address().octets()[0];

                // Reject loopback (127.0.0.0/8), multicast (224.0.0.0/4), and reserved ranges
                if first_octet == 127 || first_octet >= 224 {
                    if let Some(tx) = &self.action_tx {
                        let _ = tx.clone().try_send(Action::CidrError);
                    }
                    return;
                }

                self.cidr = Some(ip_cidr);
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
            let Some(tx) = self.action_tx.clone() else {
                self.is_scanning = false;
                return;
            };
            let semaphore = Arc::new(Semaphore::new(POOL_SIZE));

            self.task = tokio::spawn(async move {
                log::debug!("Starting CIDR scan task");
                let ips = get_ips4_from_cidr(cidr);
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
                            let client =
                                Client::new(&Config::default()).expect("Cannot create client");
                            let payload = [0; 56];
                            let mut pinger = client
                                .pinger(IpAddr::V4(ip), PingIdentifier(random()))
                                .await;
                            pinger.timeout(Duration::from_secs(2));

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
                            log::debug!("Scan task was cancelled");
                        }
                        Err(e) if e.is_panic() => {
                            log::error!("Scan task panicked: {:?}", e);
                        }
                        Err(e) => {
                            log::error!("Scan task failed: {:?}", e);
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

        // Extract Ipv4Addr for storage
        let ip_v4 = match hip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return, // Skip IPv6 for now
        };

        // Add IP immediately without hostname (will be updated asynchronously)
        if let Some(n) = self.scanned_ips.iter_mut().find(|item| item.ip == ip) {
            n.ip = ip.to_string();
            n.ip_addr = ip_v4;
        } else {
            self.scanned_ips.push(ScannedIp {
                ip: ip.to_string(),
                ip_addr: ip_v4,
                mac: String::new(),
                hostname: String::new(), // Will be filled asynchronously
                vendor: String::new(),
            });

            // Sort IPs numerically using cached parsed IP addresses
            self.scanned_ips.sort_by(|a, b| a.ip_addr.cmp(&b.ip_addr));
        }

        self.set_scrollbar_height();

        // Perform DNS lookup asynchronously in background
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

    fn set_active_subnet(&mut self, intf: &NetworkInterface) {
        let a_ip = intf.ips[0].ip().to_string();
        let ip: Vec<&str> = a_ip.split('.').collect();
        if ip.len() > 1 {
            let new_a_ip = format!("{}.{}.{}.0/24", ip[0], ip[1], ip[2]);
            self.input = Input::default().with_value(new_a_ip);

            self.set_cidr(self.input.value().to_string(), false);
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
    fn init(&mut self, area: Size) -> Result<()> {
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

    fn register_action_handler(&mut self, tx: Sender<Action>) -> Result<()> {
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
            // -- first time scan after setting of interface
            if self.active_interface.is_none() {
                self.set_active_subnet(&intf);
            }
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

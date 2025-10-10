use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use futures::StreamExt;
use futures::stream;

use ratatui::style::Stylize;

use core::str;
use port_desc::{PortDescription, TransportProtocol};
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::mpsc::Sender,
};

use super::Component;
use crate::enums::COMMON_PORTS;
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    dns_cache::DnsCache,
    enums::{PortsScanState, TabsEnum},
    layout::get_vertical_layout,
    tui::Frame,
};

// Default concurrent port scan pool size
// Used as fallback if CPU detection fails
const DEFAULT_POOL_SIZE: usize = 64;

// Minimum concurrent operations to maintain reasonable scan speed
const MIN_POOL_SIZE: usize = 32;

// Maximum concurrent operations to prevent overwhelming the network
const MAX_POOL_SIZE: usize = 128;

// Port scan timeout in seconds
// Time to wait for TCP connection before considering port closed
// 2 seconds balances thoroughness with scan speed for typical networks
const PORT_SCAN_TIMEOUT_SECS: u64 = 2;

// Animation frames for the scanning spinner
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Debug, Clone, PartialEq)]
pub struct ScannedIpPorts {
    pub ip: String,
    state: PortsScanState,
    hostname: String,
    pub ports: Vec<u16>,
}

pub struct Ports {
    active_tab: TabsEnum,
    action_tx: Option<Sender<Action>>,
    ip_ports: Vec<ScannedIpPorts>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
    port_desc: Option<PortDescription>,
    dns_cache: DnsCache,
}

impl Default for Ports {
    fn default() -> Self {
        Self::new()
    }
}

impl Ports {
    pub fn new() -> Self {
        let mut port_desc = None;
        if let Ok(pd) = PortDescription::default() {
            port_desc = Some(pd);
        }

        Self {
            active_tab: TabsEnum::Discovery,
            action_tx: None,
            ip_ports: Vec::new(),
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
            port_desc,
            dns_cache: DnsCache::new(),
        }
    }

    // Calculate optimal pool size based on available CPU cores
    // Returns a value between MIN_POOL_SIZE and MAX_POOL_SIZE
    // Port scanning uses higher limits than discovery as it's more I/O-bound
    fn get_pool_size() -> usize {
        // Try to detect number of CPU cores
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4); // Default to 4 if detection fails

        // Use 4x CPU cores for port scanning (very I/O-bound)
        let calculated = num_cpus * 4;

        // Clamp to min/max bounds
        calculated.clamp(MIN_POOL_SIZE, MAX_POOL_SIZE)
    }

    pub fn get_scanned_ports(&self) -> &Vec<ScannedIpPorts> {
        &self.ip_ports
    }

    fn process_ip(&mut self, ip: &str) {
        let Ok(ipv4) = ip.parse::<Ipv4Addr>() else {
            return;
        };

        if let Some(n) = self.ip_ports.iter_mut().find(|item| item.ip == ip) {
            n.ip = ip.to_string();
        } else {
            self.ip_ports.push(ScannedIpPorts {
                ip: ip.to_string(),
                hostname: String::new(), // Will be filled asynchronously
                state: PortsScanState::Waiting,
                ports: Vec::new(),
            });

            self.ip_ports.sort_by(|a, b| {
                // Safe: IPs were validated during insertion
                let a_ip: Ipv4Addr = a.ip.parse().expect("validated IP");
                let b_ip: Ipv4Addr = b.ip.parse().expect("validated IP");
                a_ip.cmp(&b_ip)
            });
        }

        self.set_scrollbar_height();

        // Perform DNS lookup asynchronously in background
        if let Some(tx) = self.action_tx.clone() {
            let dns_cache = self.dns_cache.clone();
            let ip_string = ip.to_string();
            let ip_addr: IpAddr = ipv4.into();
            tokio::spawn(async move {
                let hostname = dns_cache.lookup_with_timeout(ip_addr).await;
                if !hostname.is_empty() {
                    let _ = tx.try_send(Action::DnsResolved(ip_string, hostname));
                }
            });
        }
    }

    fn set_scrollbar_height(&mut self) {
        let mut ip_len = 0;
        if !self.ip_ports.is_empty() {
            ip_len = self.ip_ports.len() - 1;
        }
        self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None);
        scrollbar
    }

    fn previous_in_list(&mut self) {
        let index = match self.list_state.selected() {
            Some(index) => {
                if index == 0 {
                    if self.ip_ports.is_empty() {
                        0
                    } else {
                        self.ip_ports.len() - 1
                    }
                } else {
                    index - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_list(&mut self) {
        let index = match self.list_state.selected() {
            Some(index) => {
                let mut s_ip_len = 0;
                if !self.ip_ports.is_empty() {
                    s_ip_len = self.ip_ports.len() - 1;
                }
                if index >= s_ip_len {
                    0
                } else {
                    index + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn scan_ports(&mut self, index: usize) {
        if index >= self.ip_ports.len() {
            return; // -- index out of bounds
        }

        self.ip_ports[index].state = PortsScanState::Scanning;

        let Some(tx) = self.action_tx.clone() else {
            log::error!("Cannot scan ports: action channel not initialized");
            return;
        };
        // Safe: IP was validated during insertion
        let ip: IpAddr = self.ip_ports[index].ip.parse().expect("validated IP");
        let ports_box = Box::new(COMMON_PORTS.iter());

        // Calculate optimal pool size based on system resources
        let pool_size = Self::get_pool_size();

        tokio::spawn(async move {
            log::debug!("Starting port scan for IP: {} with pool size {}", ip, pool_size);
            let ports = stream::iter(ports_box);
            ports
                .for_each_concurrent(pool_size, |port| {
                    Self::scan(tx.clone(), index, ip, port.to_owned())
                })
                .await;

            // Report scan completion
            if let Err(e) = tx.try_send(Action::PortScanDone(index)) {
                log::error!(
                    "Failed to send port scan completion notification for {}: {:?}",
                    ip, e
                );
            }
            log::debug!("Port scan completed for IP: {}", ip);
        });
    }

    async fn scan(tx: Sender<Action>, index: usize, ip: IpAddr, port: u16) {
        let timeout = Duration::from_secs(PORT_SCAN_TIMEOUT_SECS);
        let soc_addr = SocketAddr::new(ip, port);
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&soc_addr)).await {
            // Successfully connected to port
            if let Err(e) = tx.try_send(Action::PortScan(index, port)) {
                log::error!(
                    "Failed to send open port notification for {}:{} - action channel may be full or closed: {:?}",
                    ip, port, e
                );
            }
        }
    }

    fn scan_selected(&mut self) {
        if let Some(index) = self.list_state.selected() {
            self.scan_ports(index);
        }
    }

    fn store_scanned_port(&mut self, index: usize, port: u16) {
        let ip_ports = &mut self.ip_ports[index];
        if !ip_ports.ports.contains(&port) {
            ip_ports.ports.push(port);
        }
    }

    fn make_list(&self, rect: Rect) -> List<'_> {
        let mut items = Vec::new();
        for ip in &self.ip_ports {
            let mut lines = Vec::new();

            let mut ip_line_vec = vec![
                "IP:    ".yellow(), 
                ip.ip.clone().blue(),
            ];
            if !ip.hostname.is_empty() {
                ip_line_vec.push(" (".into());
                ip_line_vec.push(ip.hostname.clone().cyan());
                ip_line_vec.push(")".into());
            }
            lines.push(Line::from(ip_line_vec));

            let mut ports_spans = vec!["PORTS: ".yellow()];
            if ip.state == PortsScanState::Waiting {
                ports_spans.push("?".red());
            } else if ip.state == PortsScanState::Scanning {
                let spinner = SPINNER_SYMBOLS[self.spinner_index];
                ports_spans.push(spinner.magenta());
            } else {
                let mut line_size = 0;

                for p in &ip.ports {
                    let port = p.to_string();
                    line_size += port.len();

                    ports_spans.push(port.green());

                    if let Some(pd) = &self.port_desc {
                        let p_type = pd.get_port_service_name(p.to_owned(), TransportProtocol::Tcp);
                        let p_type_str = format!("({})", p_type).to_string();
                        ports_spans.push(p_type_str.clone().light_magenta());
                        line_size += p_type_str.len();
                    }

                    ports_spans.push(", ".yellow());

                    let t_width: usize = (rect.width as usize) - 8;
                    if line_size >= t_width {
                        line_size = 0;
                        lines.push(Line::from(ports_spans.clone()));
                        ports_spans.clear();
                        ports_spans.push("       ".gray());
                    }
                }
            }
            lines.push(Line::from(ports_spans.clone()));

            let t = Text::from(lines);
            items.push(t);
        }

        List::new(items)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can selected", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                        ]))
                        .alignment(Alignment::Right), // .position(ratatui::widgets::block::Position::Bottom),
                    )
                    .title(
                        ratatui::widgets::block::Title::from("|Ports|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            // Unicode up/down triangle characters (▲▼)
                            String::from(char::from_u32(0x25b2).unwrap_or('▲')).red(),
                            String::from(char::from_u32(0x25bc).unwrap_or('▼')).red(),
                            Span::styled("select|", Style::default().fg(Color::Yellow)),
                        ]))
                        .position(ratatui::widgets::block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .borders(Borders::ALL)
                    .border_type(DEFAULT_BORDER_STYLE)
                    .padding(Padding::new(1, 3, 1, 1)),
            )
            .highlight_symbol("*")
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Rgb(100, 100, 100)),
            )
    }
}

impl Component for Ports {
    fn init(&mut self, area: Size) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, action_tx: Sender<Action>) -> Result<()> {
        self.action_tx = Some(action_tx);
        Ok(())
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            let mut s_index = self.spinner_index + 1;
            s_index %= SPINNER_SYMBOLS.len();
            self.spinner_index = s_index;
        }

        // -- tab change
        if let Action::TabChange(tab) = action {
            self.tab_changed(tab)?;
        }

        if self.active_tab == TabsEnum::Ports {
            // -- prev & next select item in list
            if let Action::Down = action {
                self.next_in_list();
            }
            if let Action::Up = action {
                self.previous_in_list();
            }

            if let Action::ScanCidr = action {
                self.scan_selected();
            }
        }

        if let Action::PortScan(index, port) = action {
            self.store_scanned_port(index, port);
        }

        if let Action::PortScanDone(index) = action {
            self.ip_ports[index].state = PortsScanState::Done;
        }

        // -- PING IP
        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
        }

        // -- DNS resolved
        if let Action::DnsResolved(ref ip, ref hostname) = action {
            if let Some(entry) = self.ip_ports.iter_mut().find(|item| item.ip == *ip) {
                entry.hostname = hostname.clone();
            }
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Ports {
            let layout = get_vertical_layout(area);

            let mut list_rect = layout.bottom;
            list_rect.y += 1;
            list_rect.height -= 1;

            // -- LIST
            let list = self.make_list(list_rect);
            f.render_stateful_widget(list, list_rect, &mut self.list_state.clone());

            // -- SCROLLBAR
            let scrollbar = Self::make_scrollbar();
            let mut scroll_rect = list_rect;
            scroll_rect.y += 1;
            scroll_rect.height -= 2;
            f.render_stateful_widget(
                scrollbar,
                scroll_rect.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                &mut self.scrollbar_state,
            );
        }

        Ok(())
    }
}

use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};
use futures::StreamExt;
use futures::{future::join_all, stream};

use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};
use ratatui::style::Stylize;

use core::str;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{string, time::Duration};
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::Component;
use crate::enums::COMMON_PORTS;
use crate::{
    action::Action,
    components::discovery::ScannedIp,
    config::DEFAULT_BORDER_STYLE,
    enums::{PortsScanState, TabsEnum},
    layout::get_vertical_layout,
    mode::Mode,
    tui::Frame,
};
use crossterm::event::{KeyCode, KeyEvent};
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

static POOL_SIZE: usize = 64;
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

struct ScannedIpPorts {
    ip: String,
    state: PortsScanState,
    ports: Vec<u16>,
}

pub struct Ports {
    active_tab: TabsEnum,
    action_tx: Option<UnboundedSender<Action>>,
    ip_ports: Vec<ScannedIpPorts>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
}

impl Default for Ports {
    fn default() -> Self {
        Self::new()
    }
}

impl Ports {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            action_tx: None,
            ip_ports: Vec::new(),
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
        }
    }

    fn process_ip(&mut self, ip: &str) {
        let ipv4: Ipv4Addr = ip.parse().unwrap();

        if let Some(n) = self.ip_ports.iter_mut().find(|item| item.ip == ip) {
            n.ip = ip.to_string();
        } else {
            self.ip_ports.push(ScannedIpPorts {
                ip: ip.to_string(),
                state: PortsScanState::Waiting,
                ports: Vec::new(),
            });

            self.ip_ports.sort_by(|a, b| {
                let a_ip: Ipv4Addr = a.ip.parse::<Ipv4Addr>().unwrap();
                let b_ip: Ipv4Addr = b.ip.parse::<Ipv4Addr>().unwrap();
                a_ip.partial_cmp(&b_ip).unwrap()
            });
        }

        self.set_scrollbar_height();
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
        self.ip_ports[index].state = PortsScanState::Scanning;

        let tx = self.action_tx.clone().unwrap();
        let ip: IpAddr = self.ip_ports[index].ip.parse().unwrap();
        let ports_box = Box::new(COMMON_PORTS.to_owned().into_iter());

        let h = tokio::spawn(async move {
            let ports = stream::iter(ports_box);
            ports
                .for_each_concurrent(1002, |port| Self::scan(tx.clone(), index, ip, port, 2))
                .await;
            tx.send(Action::PortScanDone(index)).unwrap();
        });
    }

    async fn scan(tx: UnboundedSender<Action>, index: usize, ip: IpAddr, port: u16, timeout: u64) {
        let timeout = Duration::from_secs(2);
        let soc_addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, TcpStream::connect(&soc_addr)).await {
            Ok(Ok(_)) => {
                tx.send(Action::PortScan(index, port)).unwrap();
                // println!("port: {:?}", port);
            }
            _ => {}
        }
    }

    fn scan_selected(&mut self) {
        let index = match self.list_state.selected() {
            Some(index) => {
                self.scan_ports(index);
            }
            None => {}
        };
    }

    fn store_scanned_port(&mut self, index: usize, port: u16) {
        let ip_ports = &mut self.ip_ports[index];
        if !ip_ports.ports.contains(&port) {
            ip_ports.ports.push(port);
        }
    }

    fn make_list(&self) -> List {
        let mut items = Vec::new();
        for ip in &self.ip_ports {
            let ip_line = Line::from(vec!["ip: ".yellow(), ip.ip.clone().blue()]);

            let mut ports_spans = vec!["ports: ".yellow()];
            if ip.state == PortsScanState::Waiting {
                ports_spans.push("?".red());
            } else if ip.state == PortsScanState::Scanning {
                let spinner = SPINNER_SYMBOLS[self.spinner_index];
                ports_spans.push(spinner.magenta());
            } else {
                for p in &ip.ports {
                    ports_spans.push(p.to_string().green());
                    ports_spans.push(", ".yellow());
                }
            }

            let ports = Line::from(ports_spans);
            let p = Text::from(vec![ip_line, ports]);

            items.push(p);
        }

        List::new(items)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from("|Ports|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can selected", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Left)
                        .position(ratatui::widgets::block::Position::Bottom),
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
    fn init(&mut self, area: Rect) -> Result<()> {
        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            let mut s_index = self.spinner_index + 1;
            s_index %= SPINNER_SYMBOLS.len() - 1;
            self.spinner_index = s_index;
        }

        // -- tab change
        if let Action::TabChange(tab) = action {
            self.tab_changed(tab).unwrap();
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

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Ports {
            let layout = get_vertical_layout(area);

            let mut list_rect = layout.bottom;
            list_rect.y += 1;
            list_rect.height -= 1;

            // -- LIST
            let list = self.make_list();
            f.render_stateful_widget(list, list_rect, &mut self.list_state.clone());

            // -- SCROLLBAR
            let scrollbar = Self::make_scrollbar();
            let mut scroll_rect = list_rect;
            scroll_rect.y += 1;
            scroll_rect.height -= 2;
            f.render_stateful_widget(
                scrollbar,
                scroll_rect.inner(&Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                &mut self.scrollbar_state,
            );
        }

        Ok(())
    }
}

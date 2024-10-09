use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};

use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};
use ratatui::style::Stylize;

use ratatui::{prelude::*, widgets::*};
use std::net::IpAddr;
use tokio::sync::mpsc::{self, UnboundedSender};
use tui_scrollview::{ScrollView, ScrollViewState};

use super::Component;
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    enums::{PacketTypeEnum, PacketsInfoTypesEnum, TabsEnum},
    layout::{get_vertical_layout, HORIZONTAL_CONSTRAINTS},
    tui::Frame,
    widgets::scroll_traffic::TrafficScroll,
};

#[derive(Clone, Debug)]
pub struct IPTraffic {
    pub ip: IpAddr,
    pub download: f64,
    pub upload: f64,
    pub hostname: String,
}

pub struct Sniffer {
    active_tab: TabsEnum,
    action_tx: Option<UnboundedSender<Action>>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    traffic_ips: Vec<IPTraffic>,
    scrollview_state: ScrollViewState,
}

impl Default for Sniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sniffer {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            action_tx: None,
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            traffic_ips: Vec::new(),
            scrollview_state: ScrollViewState::new(),
        }
    }

    fn set_scrollbar_height(&mut self) {
        // let mut ip_len = 0;
        // if !self.ip_ports.is_empty() {
        //     ip_len = self.ip_ports.len() - 1;
        // }
        // self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None);
        scrollbar
    }

    fn scroll_down(&mut self) {
        self.scrollview_state.scroll_down();
    }

    fn scroll_up(&mut self) {
        self.scrollview_state.scroll_up();
    }

    fn traffic_contains_ip(&self, ip: &IpAddr) -> bool {
        self.traffic_ips
            .iter()
            .any(|traffic| traffic.ip == ip.clone())
    }

    fn count_traffic_packet(&mut self, source: IpAddr, destination: IpAddr, length: usize) {
        // -- destination
        if self.traffic_contains_ip(&destination) {
            if let Some(ip_entry) = self.traffic_ips.iter_mut().find(|ie| ie.ip == destination) {
                ip_entry.download += length as f64;
            }
        } else {
            self.traffic_ips.push(IPTraffic {
                ip: destination,
                download: length as f64,
                upload: 0.0,
                hostname: lookup_addr(&destination).unwrap_or(String::from("unknown")),
            });
        }

        // -- source
        if self.traffic_contains_ip(&source) {
            if let Some(ip_entry) = self.traffic_ips.iter_mut().find(|ie| ie.ip == source) {
                ip_entry.upload += length as f64;
            }
        } else {
            self.traffic_ips.push(IPTraffic {
                ip: source,
                download: 0.0,
                upload: length as f64,
                hostname: lookup_addr(&source).unwrap_or(String::from("unknown")),
            });
        }

        self.traffic_ips.sort_by(|a, b| {
            let a_sum = a.download + a.upload;
            let b_sum = b.download + b.upload;
            b_sum.partial_cmp(&a_sum).unwrap()
        });
    }

    fn process_packet(&mut self, packet: PacketsInfoTypesEnum) {
        match packet {
            PacketsInfoTypesEnum::Tcp(p) => {
                self.count_traffic_packet(p.source, p.destination, p.length)
            }
            PacketsInfoTypesEnum::Udp(p) => {
                self.count_traffic_packet(p.source, p.destination, p.length)
            }
            _ => {}
        }
    }

    fn make_ips_block(&self) -> Block {
        let ips_block = Block::default()
            .title(
                ratatui::widgets::block::Title::from(Line::from(vec![
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        String::from(char::from_u32(0x25b2).unwrap_or('<')),
                        Style::default().fg(Color::Red),
                    ),
                    Span::styled(
                        String::from(char::from_u32(0x25bc).unwrap_or('>')),
                        Style::default().fg(Color::Red),
                    ),
                    Span::styled("scroll|", Style::default().fg(Color::Yellow)),
                ]))
                .position(ratatui::widgets::block::Position::Bottom)
                .alignment(Alignment::Right),
            )
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Download/Upload|",
                    Style::default().fg(Color::Yellow),
                ))
                .position(ratatui::widgets::block::Position::Top)
                .alignment(Alignment::Right),
            )
            .borders(Borders::ALL)
            .border_style(Color::Rgb(100, 100, 100))
            .border_type(BorderType::Rounded);
        ips_block
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }
}

impl Component for Sniffer {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // -- tab change
        if let Action::TabChange(tab) = action {
            self.tab_changed(tab).unwrap();
        }

        if let Action::Down = action {
            self.scroll_down();
        }

        if let Action::Up = action {
            self.scroll_up();
        }

        if let Action::PacketDump(time, packet, packet_type) = action {
            match packet_type {
                PacketTypeEnum::Tcp => self.process_packet(packet.clone()),
                PacketTypeEnum::Udp => self.process_packet(packet.clone()),
                _ => {}
            }
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Traffic {
            let layout = get_vertical_layout(area);

            // -- IPs block
            let mut ips_block_rect = layout.bottom;
            ips_block_rect.y += 1;
            ips_block_rect.height -= 1;
            let ips_layout = Layout::horizontal(HORIZONTAL_CONSTRAINTS).split(ips_block_rect);
            let b = self.make_ips_block();
            f.render_widget(b, ips_layout[0]);

            // -- scrollview
            let ips_rect = Rect {
                x: ips_layout[0].x + 1,
                y: ips_layout[0].y + 1,
                width: ips_layout[0].width - 2,
                height: ips_layout[0].height - 2,
            };
            let ips_scroll = TrafficScroll {
                traffic_ips: self.traffic_ips.clone(),
            };
            f.render_stateful_widget(ips_scroll, ips_rect, &mut self.scrollview_state);
        }

        Ok(())
    }
}

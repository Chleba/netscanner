use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};

use pnet::{
    datalink::NetworkInterface,
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
        MutablePacket, Packet,
    },
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
    utils::bytes_convert,
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
    active_interface: Option<NetworkInterface>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    traffic_ips: Vec<IPTraffic>,
    scrollview_state: ScrollViewState,
    udp_sum: f64,
    tcp_sum: f64,
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
            active_interface: None,
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            traffic_ips: Vec::new(),
            scrollview_state: ScrollViewState::new(),
            udp_sum: 0.0,
            tcp_sum: 0.0,
        }
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
                self.count_traffic_packet(p.source, p.destination, p.length);
                self.tcp_sum += p.length as f64;
            }
            PacketsInfoTypesEnum::Udp(p) => {
                self.count_traffic_packet(p.source, p.destination, p.length);
                self.udp_sum += p.length as f64;
            }
            _ => {}
        }
    }

    fn make_charts(&self) -> BarChart {
        BarChart::default()
            .direction(Direction::Vertical)
            .bar_width(12)
            .bar_gap(4)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .value(self.udp_sum as u64)
                        .text_value(bytes_convert(self.udp_sum))
                        .label("UDP".into())
                        .style(Color::Yellow),
                    Bar::default()
                        .value(self.tcp_sum as u64)
                        .text_value(bytes_convert(self.tcp_sum))
                        .label("TCP".into())
                        .style(Color::Green),
                ]),
            )
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

    fn make_sum_block(&self) -> Block {
        let ips_block = Block::default()
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Summary|",
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

    fn make_charts_block(&self) -> Block {
        Block::default()
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Protocols sum|",
                    Style::default().fg(Color::Yellow),
                ))
                .position(ratatui::widgets::block::Position::Top)
                .alignment(Alignment::Right),
            )
            .borders(Borders::ALL)
            .border_style(Color::Rgb(100, 100, 100))
            .border_type(BorderType::Rounded)
    }

    fn render_summary(&mut self, f: &mut Frame<'_>, area: Rect) {
        if !self.traffic_ips.is_empty() {
            let total_download = Line::from(vec![
                "Total download: ".into(),
                bytes_convert(self.traffic_ips[0].download).green(),
            ]);
            f.render_widget(
                total_download,
                Rect {
                    x: area.x + 2,
                    y: area.y + 2,
                    width: area.width / 2,
                    height: 1,
                },
            );

            let total_upload = Line::from(vec![
                "Total upload: ".into(),
                bytes_convert(self.traffic_ips[0].upload).red(),
            ]);
            f.render_widget(
                total_upload,
                Rect {
                    x: area.x + (area.width / 2) + 2,
                    y: area.y + 2,
                    width: area.width / 2,
                    height: 1,
                },
            );

            let top_uploader = Line::from(vec!["Top uploader:".into()]);
            f.render_widget(
                top_uploader,
                Rect {
                    x: area.x + 2,
                    y: area.y + 4,
                    width: area.width,
                    height: 1,
                },
            );
        }
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

        if let Action::ActiveInterface(ref interface) = action {
            self.active_interface = Some(interface.clone());
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

            // -- summary
            let sum_layout =
                Layout::vertical([Constraint::Percentage(30), Constraint::Percentage(70)])
                    .split(ips_layout[1]);
            let sum_block = self.make_sum_block();
            f.render_widget(sum_block, sum_layout[0]);

            self.render_summary(f, sum_layout[0]);

            // -- charts
            let charts_block = self.make_charts_block();
            f.render_widget(charts_block, sum_layout[1]);

            let charts = self.make_charts();
            let charts_rect = Rect {
                x: sum_layout[1].x + 2,
                y: sum_layout[1].y + 2,
                width: sum_layout[1].width - 5,
                height: sum_layout[1].height - 3,
            };
            f.render_widget(charts, charts_rect);
        }

        Ok(())
    }
}

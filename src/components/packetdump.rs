use chrono::{DateTime, Local};
use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ipnetwork::Ipv4Network;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    MutablePacket, Packet,
};
use pnet::util::MacAddr;
use ratatui::{prelude::*, widgets::*};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task,
};

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
    utils::MaxSizeVec,
};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};

#[derive(Default, Clone, Copy, Display, FromRepr, EnumIter, PartialEq, Debug)]
pub enum PacketTypeEnum {
    #[default]
    #[strum(to_string = "All")]
    All,
    #[strum(to_string = "ARP")]
    Arp,
    #[strum(to_string = "TCP")]
    Tcp,
    #[strum(to_string = "UDP")]
    Udp,
    #[strum(to_string = "ICMP")]
    Icmp,
}

impl PacketTypeEnum {
    fn previous(&self) -> Self {
        let current_index: usize = *self as usize;
        let previous_index = current_index.saturating_sub(1);
        Self::from_repr(previous_index).unwrap_or(*self)
    }

    fn next(&self) -> Self {
        let current_index = *self as usize;
        let next_index = current_index.saturating_add(1);
        Self::from_repr(next_index).unwrap_or(*self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArpPacketData {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub struct PacketDump {
    action_tx: Option<UnboundedSender<Action>>,
    loop_thread: Option<JoinHandle<()>>,
    should_quit: bool,
    active_interface: Option<NetworkInterface>,
    show_packets: bool,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    packet_type: PacketTypeEnum,
    arp_packets: MaxSizeVec<(DateTime<Local>, String)>,
    udp_packets: MaxSizeVec<(DateTime<Local>, String)>,
    tcp_packets: MaxSizeVec<(DateTime<Local>, String)>,
    icmp_packets: MaxSizeVec<(DateTime<Local>, String)>,
    all_packets: MaxSizeVec<(DateTime<Local>, String)>,
}

impl Default for PacketDump {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketDump {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            loop_thread: None,
            should_quit: false,
            active_interface: None,
            show_packets: false,
            table_state: TableState::default().with_selected(0),
            scrollbar_state: ScrollbarState::new(0),
            packet_type: PacketTypeEnum::All,
            arp_packets: MaxSizeVec::new(1000),
            udp_packets: MaxSizeVec::new(1000),
            tcp_packets: MaxSizeVec::new(1000),
            icmp_packets: MaxSizeVec::new(1000),
            all_packets: MaxSizeVec::new(1000),
        }
    }

    fn handle_udp_packet(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        packet: &[u8],
        tx: UnboundedSender<Action>,
    ) {
        let udp = UdpPacket::new(packet);
        if let Some(udp) = udp {
            tx.send(Action::PacketDump(
                Local::now(),
                format!(
                    "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                    interface_name,
                    source,
                    udp.get_source(),
                    destination,
                    udp.get_destination(),
                    udp.get_length()
                ),
                PacketTypeEnum::Udp,
            ))
            .unwrap();
        }
    }

    fn handle_icmp_packet(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        packet: &[u8],
        tx: UnboundedSender<Action>,
    ) {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    tx.send(Action::PacketDump(
                        Local::now(),
                        format!(
                            "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                            interface_name,
                            source,
                            destination,
                            echo_reply_packet.get_sequence_number(),
                            echo_reply_packet.get_identifier()
                        ),
                        PacketTypeEnum::Icmp,
                    ))
                    .unwrap();
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    tx.send(Action::PacketDump(
                        Local::now(),
                        format!(
                            "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                            interface_name,
                            source,
                            destination,
                            echo_request_packet.get_sequence_number(),
                            echo_request_packet.get_identifier()
                        ),
                        PacketTypeEnum::Icmp,
                    ))
                    .unwrap();
                }
                _ => {
                    tx.send(Action::PacketDump(
                        Local::now(),
                        format!(
                            "[{}]: ICMP packet {} -> {} (type={:?})",
                            interface_name,
                            source,
                            destination,
                            icmp_packet.get_icmp_type()
                        ),
                        PacketTypeEnum::Icmp,
                    ))
                    .unwrap();
                }
            }
        }
    }

    fn handle_tcp_packet(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        packet: &[u8],
        tx: UnboundedSender<Action>,
    ) {
        let tcp = TcpPacket::new(packet);
        if let Some(tcp) = tcp {
            tx.send(Action::PacketDump(
                Local::now(),
                format!(
                    "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len()
                ),
                PacketTypeEnum::Tcp,
            ))
            .unwrap();
        }
    }

    fn handle_transport_protocol(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
        tx: UnboundedSender<Action>,
    ) {
        match protocol {
            IpNextHeaderProtocols::Udp => {
                Self::handle_udp_packet(interface_name, source, destination, packet, tx)
            }
            IpNextHeaderProtocols::Tcp => {
                Self::handle_tcp_packet(interface_name, source, destination, packet, tx)
            }
            IpNextHeaderProtocols::Icmp => {
                Self::handle_icmp_packet(interface_name, source, destination, packet, tx)
            }
            _ => {} // _ => println!(
                    //     "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                    //     interface_name,
                    //     match source {
                    //         IpAddr::V4(..) => "IPv4",
                    //         _ => "IPv6",
                    //     },
                    //     source,
                    //     destination,
                    //     protocol,
                    //     packet.len()
                    // ),
        }
    }

    fn handle_ipv4_packet(
        interface_name: &str,
        ethernet: &EthernetPacket,
        tx: UnboundedSender<Action>,
    ) {
        let header = Ipv4Packet::new(ethernet.payload());
        if let Some(header) = header {
            Self::handle_transport_protocol(
                interface_name,
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.get_next_level_protocol(),
                header.payload(),
                tx,
            );
        }
    }

    fn handle_arp_packet(
        interface_name: &str,
        ethernet: &EthernetPacket,
        tx: UnboundedSender<Action>,
    ) {
        let header = ArpPacket::new(ethernet.payload());
        if let Some(header) = header {
            tx.send(Action::ArpRecieve(ArpPacketData {
                sender_mac: header.get_sender_hw_addr(),
                sender_ip: header.get_sender_proto_addr(),
                target_mac: header.get_target_hw_addr(),
                target_ip: header.get_target_proto_addr(),
            }))
            .unwrap();

            tx.send(Action::PacketDump(
                Local::now(),
                format!(
                    "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                    interface_name,
                    ethernet.get_source(),
                    header.get_sender_proto_addr(),
                    ethernet.get_destination(),
                    header.get_target_proto_addr(),
                    header.get_operation()
                ),
                PacketTypeEnum::Arp,
            ))
            .unwrap();
        }
    }

    fn handle_ethernet_frame(
        interface: &NetworkInterface,
        ethernet: &EthernetPacket,
        tx: UnboundedSender<Action>,
    ) {
        let interface_name = &interface.name[..];
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => Self::handle_ipv4_packet(interface_name, ethernet, tx),
            EtherTypes::Arp => Self::handle_arp_packet(interface_name, ethernet, tx),
            _ => {}
        }
    }

    fn t_logic(tx: UnboundedSender<Action>, interface: NetworkInterface) {
        let (_, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        loop {
            let mut buf: [u8; 1600] = [0u8; 1600];
            let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

            match receiver.next() {
                Ok(packet) => {
                    let payload_offset;
                    if cfg!(any(target_os = "macos", target_os = "ios"))
                        && interface.is_up()
                        && !interface.is_broadcast()
                        && ((!interface.is_loopback() && interface.is_point_to_point())
                            || interface.is_loopback())
                    {
                        if interface.is_loopback() {
                            // The pnet code for BPF loopback adds a zero'd out Ethernet header
                            payload_offset = 14;
                        } else {
                            // Maybe is TUN interface
                            payload_offset = 0;
                        }
                        if packet.len() > payload_offset {
                            let version = Ipv4Packet::new(&packet[payload_offset..])
                                .unwrap()
                                .get_version();
                            if version == 4 {
                                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                                fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                                Self::handle_ethernet_frame(
                                    &interface,
                                    &fake_ethernet_frame.to_immutable(),
                                    tx.clone(),
                                );
                                continue;
                            }
                        }
                    }
                    Self::handle_ethernet_frame(
                        &interface,
                        &EthernetPacket::new(packet).unwrap(),
                        tx.clone(),
                    );
                }
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }

    fn start_loop(&mut self) {
        if self.loop_thread.is_none() {
            let tx = self.action_tx.clone().unwrap();
            let interface = self.active_interface.clone().unwrap();
            let t_handle = thread::spawn(move || {
                Self::t_logic(tx, interface);
            });
            self.loop_thread = Some(t_handle);
        }
    }

    fn get_array_by_packet_type(
        &mut self,
        packet_type: PacketTypeEnum,
    ) -> &Vec<(DateTime<Local>, String)> {
        match packet_type {
            PacketTypeEnum::Arp => &mut self.arp_packets.get_vec(),
            PacketTypeEnum::Tcp => &mut self.tcp_packets.get_vec(),
            PacketTypeEnum::Udp => &mut self.udp_packets.get_vec(),
            PacketTypeEnum::Icmp => &mut self.icmp_packets.get_vec(),
            PacketTypeEnum::All => &mut self.all_packets.get_vec(),
        }
    }

    fn set_scrollbar_height(&mut self) {
        let logs_len = self.get_array_by_packet_type(self.packet_type).len();
        self.scrollbar_state = self.scrollbar_state.content_length(logs_len - 1);
    }

    fn previous_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                let logs = self.get_array_by_packet_type(self.packet_type);
                if index == 0 {
                    logs.len() - 1
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
                let logs = self.get_array_by_packet_type(self.packet_type);
                if index >= logs.len() - 1 {
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

    fn get_table_rows_by_packet_type<'a>(&mut self, packet_type: PacketTypeEnum) -> Vec<Row<'a>> {
        let logs = self.get_array_by_packet_type(packet_type);
        let rows: Vec<Row> = logs
            .iter()
            .map(|(time, log)| {
                let t = time.format("%H:%M:%S").to_string();
                let l = <String as Clone>::clone(&log);
                Row::new(vec![
                    Cell::from(t.red()),
                    Cell::from(l.green()),
                ])
            })
            .collect();
        rows
    }

    fn make_table<'a>(rows: Vec<Row<'a>>, packet_type: PacketTypeEnum) -> Table<'a> {
        let header = Row::new(vec!["time", "packet log"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);

        let table = Table::new(rows, [Constraint::Min(10), Constraint::Percentage(100)])
            .header(header)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from("|Packets|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            String::from(char::from_u32(0x25c0).unwrap_or('<')).red(),
                            // PacketTypeEnum::iter().map(|p| {
                            //     if p == packet_type {
                            //         p.to_string().red()
                            //     } else {
                            //         p.to_string().green()
                            //     }
                            // }).collect(Vec<Span>),
                            Span::styled(
                                packet_type.to_string(),
                                Style::default().fg(Color::Yellow),
                            ),
                            String::from(char::from_u32(0x25b6).unwrap_or('>')).red(),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                        ]))
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
                        .alignment(Alignment::Left),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|hide ", Style::default().fg(Color::Yellow)),
                            Span::styled("p", Style::default().fg(Color::Red)),
                            Span::styled("ackets|", Style::default().fg(Color::Yellow)),
                        ]))
                        .position(ratatui::widgets::block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .borders(Borders::ALL), // .padding(Padding::new(1, 0, 2, 0)),
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
}

impl Component for PacketDump {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // -- active interface set
        if let Action::ActiveInterface(ref interface) = action {
            let mut was_none = false;
            if self.active_interface.is_none() {
                was_none = true;
            }
            self.active_interface = Some(interface.clone());
            if was_none {
                self.start_loop();
            }
        }
        if self.show_packets {
            // -- prev & next select item in table
            if let Action::Down = action {
                self.next_in_table();
            }
            if let Action::Up = action {
                self.previous_in_table();
            }
            if let Action::Left = action {
                self.packet_type = self.packet_type.previous();
                self.set_scrollbar_height();
                self.table_state.select(Some(0));
                self.set_scrollbar_height();
            }
            if let Action::Right = action {
                self.packet_type = self.packet_type.next();
                self.set_scrollbar_height();
                self.table_state.select(Some(0));
                self.set_scrollbar_height();
            }
        }
        // -- packets toggle
        if let Action::PacketToggle = action {
            self.show_packets = !self.show_packets;
        }
        // -- packet recieved
        if let Action::PacketDump(time, packet_str, packet_type) = action {
            match packet_type {
                PacketTypeEnum::Tcp => self.tcp_packets.push((time, packet_str.clone())),
                PacketTypeEnum::Arp => self.arp_packets.push((time, packet_str.clone())),
                PacketTypeEnum::Udp => self.udp_packets.push((time, packet_str.clone())),
                PacketTypeEnum::Icmp => self.icmp_packets.push((time, packet_str.clone())),
                _ => {}
            }
            self.all_packets.push((time, packet_str));
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.show_packets {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(area);
            let mut table_rect = layout[1];
            table_rect.y += 1;
            table_rect.height -= 1;

            // -- TABLE
            let rows = self.get_table_rows_by_packet_type(self.packet_type.clone());
            let table = Self::make_table(rows, self.packet_type.clone());
            f.render_stateful_widget(table, table_rect, &mut self.table_state.clone());

            // -- SCROLLBAR
            let scrollbar = Self::make_scrollbar();
            let mut scroll_rect = table_rect;
            scroll_rect.y += 1;
            scroll_rect.height -= 1;
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

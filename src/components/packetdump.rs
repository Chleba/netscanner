use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    thread::{self, JoinHandle},
    time::Duration,
};

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

#[derive(Debug, Clone, PartialEq)]
pub enum PacketTypeEnum {
    Arp,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArpPacketData {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

// struct

pub struct PacketDump {
    action_tx: Option<UnboundedSender<Action>>,
    loop_thread: Option<JoinHandle<()>>,
    should_quit: bool,
    active_interface: Option<NetworkInterface>,
    show_packets: bool,
    arp_packets: MaxSizeVec<String>,
    udp_packets: MaxSizeVec<String>,
    tcp_packets: MaxSizeVec<String>,
    icmp_packets: MaxSizeVec<String>,
    all_packets: MaxSizeVec<String>,
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
            _ => {}
            // _ => println!(
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

    fn make_list(&self, packet_type: PacketTypeEnum) -> List<'static> {
        let items: Vec<ListItem> = Vec::new();
        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("|Packets|")
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        String::from(char::from_u32(0x25b2).unwrap_or('^')).red(),
                        String::from(char::from_u32(0x25bc).unwrap_or('&')).red(),
                        String::from(char::from_u32(0x25c0).unwrap_or('<')).red(),
                        String::from(char::from_u32(0x25b6).unwrap_or('>')).red(),
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
                .title_style(Style::default().fg(Color::Yellow))
                .title_alignment(Alignment::Right),
        );
        list
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
        // -- packets toggle
        if let Action::PacketToggle = action {
            self.show_packets = !self.show_packets;
        }
        // -- packet recieved
        if let Action::PacketDump(packet_str, packet_type) = action {
            match packet_type {
                PacketTypeEnum::Tcp => self.tcp_packets.push(packet_str),
                PacketTypeEnum::Arp => self.arp_packets.push(packet_str),
                PacketTypeEnum::Udp => self.udp_packets.push(packet_str),
                PacketTypeEnum::Icmp => self.icmp_packets.push(packet_str),
            }
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.show_packets {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(area);
            let mut list_rect = layout[1];
            list_rect.y += 1;
            list_rect.height -= 1;

            // -- LIST
            let list = self.make_list(PacketTypeEnum::Arp);
            f.render_widget(list, list_rect);
        }
        Ok(())
    }
}

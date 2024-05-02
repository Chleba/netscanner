use chrono::{DateTime, Local};
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{KeyCode, KeyEvent};
use crossterm::style::Stylize;
use ipnetwork::Ipv4Network;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};
use pnet::packet::PrimitiveValues;
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    MutablePacket, Packet,
};
use pnet::util::MacAddr;
use ratatui::{prelude::*, widgets::*};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
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
    enums::{
        ARPPacketInfo, ICMP6PacketInfo, ICMPPacketInfo, PacketTypeEnum, PacketsInfoTypesEnum,
        TCPPacketInfo, UDPPacketInfo,
    },
    utils::MaxSizeVec,
};
use strum::{EnumCount, IntoEnumIterator};

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
    dump_paused: Arc<AtomicBool>,
    active_interface: Option<NetworkInterface>,
    show_packets: bool,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    packet_type: PacketTypeEnum,

    arp_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
    udp_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
    tcp_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
    icmp_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
    icmp6_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
    all_packets: MaxSizeVec<(DateTime<Local>, PacketsInfoTypesEnum)>,
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
            dump_paused: Arc::new(AtomicBool::new(false)),
            active_interface: None,
            show_packets: false,
            table_state: TableState::default().with_selected(0),
            scrollbar_state: ScrollbarState::new(0),
            packet_type: PacketTypeEnum::All,

            arp_packets: MaxSizeVec::new(1000),
            udp_packets: MaxSizeVec::new(1000),
            tcp_packets: MaxSizeVec::new(1000),
            icmp_packets: MaxSizeVec::new(1000),
            icmp6_packets: MaxSizeVec::new(1000),
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
                PacketsInfoTypesEnum::Udp(UDPPacketInfo {
                    interface_name: interface_name.to_string(),
                    source,
                    source_port: udp.get_source(),
                    destination,
                    destination_port: udp.get_destination(),
                    length: udp.get_length(),
                }),
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
                        PacketsInfoTypesEnum::Icmp(ICMPPacketInfo {
                            interface_name: interface_name.to_string(),
                            source,
                            destination,
                            seq: echo_reply_packet.get_sequence_number(),
                            id: echo_reply_packet.get_identifier(),
                            icmp_type: IcmpTypes::EchoReply,
                        }),
                        PacketTypeEnum::Icmp,
                    ))
                    .unwrap();
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    tx.send(Action::PacketDump(
                        Local::now(),
                        PacketsInfoTypesEnum::Icmp(ICMPPacketInfo {
                            interface_name: interface_name.to_string(),
                            source,
                            destination,
                            seq: echo_request_packet.get_sequence_number(),
                            id: echo_request_packet.get_identifier(),
                            icmp_type: IcmpTypes::EchoRequest,
                        }),
                        PacketTypeEnum::Icmp,
                    ))
                    .unwrap();
                }
                _ => {
                    // tx.send(Action::PacketDump(
                    //     Local::now(),
                    //     // format!(
                    //     //     "[{}]: ICMP packet {} -> {} (type={:?})",
                    //     //     interface_name,
                    //     //     source,
                    //     //     destination,
                    //     //     icmp_packet.get_icmp_type()
                    //     // ),
                    //     PacketTypeEnum::Icmp,
                    // ))
                    // .unwrap();
                }
            }
        }
    }

    fn handle_icmpv6_packet(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        packet: &[u8],
        tx: UnboundedSender<Action>,
    ) {
        let icmpv6_packet = Icmpv6Packet::new(packet);
        if let Some(icmpv6_packet) = icmpv6_packet {
            tx.send(Action::PacketDump(
                Local::now(),
                PacketsInfoTypesEnum::Icmp6(ICMP6PacketInfo {
                    interface_name: interface_name.to_string(),
                    source,
                    destination,
                    icmp_type: icmpv6_packet.get_icmpv6_type(),
                }),
                PacketTypeEnum::Icmp6,
            ))
            .unwrap();
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
                PacketsInfoTypesEnum::Tcp(TCPPacketInfo {
                    interface_name: interface_name.to_string(),
                    source,
                    source_port: tcp.get_source(),
                    destination,
                    destination_port: tcp.get_destination(),
                    length: packet.len(),
                }),
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
            IpNextHeaderProtocols::Icmpv6 => {
                Self::handle_icmpv6_packet(interface_name, source, destination, packet, tx)
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

    fn handle_ipv6_packet(
        interface_name: &str,
        ethernet: &EthernetPacket,
        tx: UnboundedSender<Action>,
    ) {
        let header = Ipv6Packet::new(ethernet.payload());
        if let Some(header) = header {
            Self::handle_transport_protocol(
                interface_name,
                IpAddr::V6(header.get_source()),
                IpAddr::V6(header.get_destination()),
                header.get_next_header(),
                header.payload(),
                tx,
            );
        } else {
            println!("[{}]: Malformed IPv6 Packet", interface_name);
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
                PacketsInfoTypesEnum::Arp(ARPPacketInfo {
                    interface_name: interface_name.to_string(),
                    source_mac: ethernet.get_source(),
                    source_ip: header.get_sender_proto_addr(),
                    destination_mac: ethernet.get_destination(),
                    destination_ip: header.get_target_proto_addr(),
                    operation: header.get_operation(),
                }),
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
            EtherTypes::Ipv6 => Self::handle_ipv6_packet(interface_name, ethernet, tx),
            EtherTypes::Arp => Self::handle_arp_packet(interface_name, ethernet, tx),
            _ => {}
        }
    }

    fn t_logic(tx: UnboundedSender<Action>, interface: NetworkInterface, paused: Arc<AtomicBool>) {
        let (_, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                tx.send(Action::Error("Unknown or unsopported channel type".into()))
                    .unwrap();
                return;
            }
            Err(e) => {
                tx.send(Action::Error(format!(
                    "Unable to create datalink channel: {e}"
                )))
                .unwrap();
                return;
            } // Ok(_) => panic!("Unknown channel type"),
              // Err(e) => panic!("Error happened {}", e),
        };
        // while !paused.load(Ordering::Relaxed) {
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
                            } else if version == 6 {
                                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
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
            let paused = self.dump_paused.clone();
            let t_handle = thread::spawn(move || {
                Self::t_logic(tx, interface, paused);
            });
            self.loop_thread = Some(t_handle);
        }
    }

    fn get_array_by_packet_type(
        &mut self,
        packet_type: PacketTypeEnum,
    ) -> &Vec<(DateTime<Local>, PacketsInfoTypesEnum)> {
        match packet_type {
            PacketTypeEnum::Arp => self.arp_packets.get_vec(),
            PacketTypeEnum::Tcp => self.tcp_packets.get_vec(),
            PacketTypeEnum::Udp => self.udp_packets.get_vec(),
            PacketTypeEnum::Icmp => self.icmp_packets.get_vec(),
            PacketTypeEnum::Icmp6 => self.icmp6_packets.get_vec(),
            PacketTypeEnum::All => self.all_packets.get_vec(),
        }
    }

    fn set_scrollbar_height(&mut self) {
        let logs_len = self.get_array_by_packet_type(self.packet_type).len();
        if logs_len > 0 {
            self.scrollbar_state = self.scrollbar_state.content_length(logs_len - 1);
        }
    }

    fn previous_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                let logs = self.get_array_by_packet_type(self.packet_type);
                let logs_len = logs.len();
                if index == 0 {
                    if logs_len > 0 {
                        logs.len() - 1
                    } else {
                        0
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
                let mut spans = vec![];
                match log {
                    // -----------------------------
                    // -- ICMP
                    PacketsInfoTypesEnum::Icmp(icmp) => {
                        spans.push(Span::styled(
                            format!("[{}] ", icmp.interface_name.clone()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            "ICMP",
                            Style::default().fg(Color::Black).bg(Color::White),
                        ));
                        match icmp.icmp_type {
                            IcmpTypes::EchoRequest => {
                                spans.push(Span::styled(
                                    " echo request ",
                                    Style::default().fg(Color::Yellow),
                                ));
                            }
                            IcmpTypes::EchoReply => {
                                spans.push(Span::styled(
                                    " echo reply ",
                                    Style::default().fg(Color::Yellow),
                                ));
                            }
                            _ => {}
                        }
                        spans.push(Span::styled(
                            format!("{}", icmp.source.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(" -> ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", icmp.destination.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled("(seq=", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{:?}", icmp.seq.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(", ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled("id=", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{:?}", icmp.id.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(")", Style::default().fg(Color::Yellow)));
                    }
                    // -----------------------------
                    // -- ICMP6
                    PacketsInfoTypesEnum::Icmp6(icmp) => {
                        spans.push(Span::styled(
                            format!("[{}] ", icmp.interface_name.clone()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            "ICMP6",
                            Style::default().fg(Color::Red).bg(Color::Black),
                        ));

                        let mut icmp_type_str = " unknown ";
                        match icmp.icmp_type {
                            Icmpv6Types::EchoRequest => {
                                icmp_type_str = " echo request ";
                            }
                            Icmpv6Types::EchoReply => {
                                icmp_type_str = " echo reply ";
                            }
                            Icmpv6Types::NeighborAdvert => {
                                icmp_type_str = " neighbor advert ";
                            }
                            Icmpv6Types::NeighborSolicit => {
                                icmp_type_str = " neighbor solicit ";
                            }
                            Icmpv6Types::Redirect => {
                                icmp_type_str = " redirect ";
                            }
                            _ => {}
                        }
                        spans.push(Span::styled(
                            icmp_type_str,
                            Style::default().fg(Color::Yellow),
                        ));

                        spans.push(Span::styled(
                            format!("{}", icmp.source.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(" -> ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", icmp.destination.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(", ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(")", Style::default().fg(Color::Yellow)));
                    }
                    // -----------------------------
                    // -- UDP
                    PacketsInfoTypesEnum::Udp(udp) => {
                        spans.push(Span::styled(
                            format!("[{}] ", udp.interface_name.clone()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            "UDP",
                            Style::default().fg(Color::Yellow).bg(Color::Blue),
                        ));
                        spans.push(Span::styled(
                            " Packet: ",
                            Style::default().fg(Color::Yellow),
                        ));
                        spans.push(Span::styled(
                            format!("{}", udp.source.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(":", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", udp.source_port.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(" > ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", udp.destination.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(":", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", udp.destination_port.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(";", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            " length: ",
                            Style::default().fg(Color::Yellow),
                        ));
                        spans.push(Span::styled(
                            format!("{}", udp.length),
                            Style::default().fg(Color::Red),
                        ));
                    }
                    // -----------------------------
                    // -- TCP
                    PacketsInfoTypesEnum::Tcp(tcp) => {
                        spans.push(Span::styled(
                            format!("[{}] ", tcp.interface_name.clone()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            "TCP",
                            Style::default().fg(Color::Black).bg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            " Packet: ",
                            Style::default().fg(Color::Yellow),
                        ));
                        spans.push(Span::styled(
                            format!("{}", tcp.source.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(":", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", tcp.source_port.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(" > ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", tcp.destination.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(":", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", tcp.destination_port.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(";", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            " length: ",
                            Style::default().fg(Color::Yellow),
                        ));
                        spans.push(Span::styled(
                            format!("{}", tcp.length),
                            Style::default().fg(Color::Red),
                        ));
                    }
                    // -----------------------------
                    // -- ARP
                    PacketsInfoTypesEnum::Arp(arp) => {
                        spans.push(Span::styled(
                            format!("[{}] ", arp.interface_name.clone()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            "ARP",
                            Style::default().fg(Color::Yellow).bg(Color::Red),
                        ));
                        spans.push(Span::styled(
                            " Packet: ",
                            Style::default().fg(Color::Yellow),
                        ));
                        spans.push(Span::styled(
                            format!("{}", arp.source_mac.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            format!("({})", arp.source_ip.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(" > ", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!("{}", arp.destination_mac.to_string()),
                            Style::default().fg(Color::Green),
                        ));
                        spans.push(Span::styled(
                            format!("({})", arp.destination_ip.to_string()),
                            Style::default().fg(Color::Blue),
                        ));
                        spans.push(Span::styled(";", Style::default().fg(Color::Yellow)));
                        spans.push(Span::styled(
                            format!(" {:?}", arp.operation),
                            Style::default().fg(Color::Red),
                        ));
                    }
                }
                let line = Line::from(spans);
                Row::new(vec![
                    Cell::from(Span::styled(t, Style::default().fg(Color::Cyan))),
                    Cell::from(line),
                ])
            })
            .collect();
        rows
    }

    fn make_state_toast(&mut self) -> Paragraph<'static> {
        let mut text = Span::styled(
            "..running..",
            Style::default().bg(Color::Green).fg(Color::Black),
        );
        if self.dump_paused.load(Ordering::Relaxed) {
            text = Span::styled(
                "..stopped..",
                Style::default().bg(Color::Red).fg(Color::White),
            );
        }
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::raw("|"),
                        Span::styled(
                            "d",
                            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                        ),
                        Span::styled("ump", Style::default().fg(Color::Yellow)),
                        Span::raw("|"),
                    ]))
                    .alignment(Alignment::Right)
                    .position(ratatui::widgets::block::Position::Bottom),
                ),
        )
    }

    fn make_table<'a>(rows: Vec<Row<'a>>, packet_type: PacketTypeEnum) -> Table<'a> {
        let header = Row::new(vec!["time", "packet log"])
            .style(Style::default().fg(Color::Yellow))
            .top_margin(1)
            .bottom_margin(1);

        let mut type_titles = vec![
            Span::styled("|", Style::default().fg(Color::Yellow)),
            Span::styled(
                String::from(char::from_u32(0x25c0).unwrap_or('<')),
                Style::default().fg(Color::Red),
            ),
        ];
        let mut enum_titles = PacketTypeEnum::iter()
            .enumerate()
            .map(|(idx, p)| {
                let mut span_str = format!("{} ", p);
                if idx == PacketTypeEnum::COUNT - 1 {
                    span_str = format!("{}", p);
                }
                if p == packet_type {
                    Span::styled(span_str, Style::default().fg(Color::Red))
                } else {
                    Span::styled(span_str, Style::default().fg(Color::Yellow))
                }
            })
            .collect::<Vec<Span>>();
        type_titles.append(&mut enum_titles);
        type_titles.push(Span::styled(
            String::from(char::from_u32(0x25b6).unwrap_or('>')),
            Style::default().fg(Color::Red),
        ));
        type_titles.push(Span::styled("|", Style::default().fg(Color::Yellow)));

        let table = Table::new(rows, [Constraint::Min(10), Constraint::Percentage(100)])
            .header(header)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from(Span::styled(
                            "|Packets|",
                            Style::default().fg(Color::Yellow),
                        ))
                        .position(ratatui::widgets::block::Position::Top)
                        .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(type_titles))
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Left),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                String::from(char::from_u32(0x25b2).unwrap_or('>')),
                                Style::default().fg(Color::Red),
                            ),
                            Span::styled(
                                String::from(char::from_u32(0x25bc).unwrap_or('>')),
                                Style::default().fg(Color::Red),
                            ),
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
            .highlight_symbol(Span::styled(
                String::from(char::from_u32(0x25b6).unwrap_or('>')),
                Style::default().fg(Color::Red),
            ))
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
        // -- dumping toggle
        if let Action::DumpToggle = action {
            if self.dump_paused.load(Ordering::Relaxed) {
                self.dump_paused.store(false, Ordering::Relaxed);
                self.start_loop();
            } else {
                self.dump_paused.store(true, Ordering::Relaxed);
                self.loop_thread = None;
            }
        }
        // -- packet recieved
        if !self.dump_paused.load(Ordering::Relaxed) {
            if let Action::PacketDump(time, packet, packet_type) = action {
                match packet_type {
                    PacketTypeEnum::Tcp => self.tcp_packets.push((time, packet.clone())),
                    PacketTypeEnum::Arp => self.arp_packets.push((time, packet.clone())),
                    PacketTypeEnum::Udp => self.udp_packets.push((time, packet.clone())),
                    PacketTypeEnum::Icmp => self.icmp_packets.push((time, packet.clone())),
                    PacketTypeEnum::Icmp6 => self.icmp6_packets.push((time, packet.clone())),
                    _ => {}
                }
                self.all_packets.push((time, packet.clone()));
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
            let mut table_rect = layout[1];
            table_rect.y += 1;
            table_rect.height -= 1;

            // -- TABLE
            let rows = self.get_table_rows_by_packet_type(self.packet_type);
            let table = Self::make_table(rows, self.packet_type);
            f.render_stateful_widget(table, table_rect, &mut self.table_state.clone());

            // -- STATE TOAST
            let toast = self.make_state_toast();
            let toast_react = Rect::new(table_rect.width - 14, table_rect.y + 1, 13, 3);
            f.render_widget(toast, toast_react);

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

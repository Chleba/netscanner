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
    ipv4::Ipv4Packet,
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
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
};

pub struct PacketDump {
    action_tx: Option<UnboundedSender<Action>>,
    loop_thread: Option<JoinHandle<()>>,
    should_quit: bool,
    active_interface: Option<NetworkInterface>,
    ips: Vec<Ipv4Addr>,
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
            ips: vec![],
        }
    }

    fn send_arp(&mut self, target_ip: Ipv4Addr) {
        let active_interface = self.active_interface.clone().unwrap();

        let ipv4 = active_interface
            .clone()
            .ips
            .iter()
            .find(|f| f.is_ipv4())
            .unwrap()
            .clone();
        let source_ip: Ipv4Addr = ipv4.ip().to_string().parse().unwrap();

        let (mut sender, _) = match pnet::datalink::channel(&active_interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(active_interface.mac.unwrap());
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(active_interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        sender
            .send_to(ethernet_packet.packet(), None)
            .unwrap()
            .unwrap();
    }

    fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
        let header = ArpPacket::new(ethernet.payload());
        if let Some(header) = header {
            println!(
                "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                interface_name,
                ethernet.get_source(),
                header.get_sender_proto_addr(),
                ethernet.get_destination(),
                header.get_target_proto_addr(),
                header.get_operation()
            );
        } else {
            println!("[{}]: Malformed ARP Packet", interface_name);
        }
    }

    fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
        let interface_name = &interface.name[..];
        match ethernet.get_ethertype() {
            EtherTypes::Arp => Self::handle_arp_packet(interface_name, ethernet),
            _ => {}
            // _ => println!(
            //     "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            //     interface_name,
            //     ethernet.get_source(),
            //     ethernet.get_destination(),
            //     ethernet.get_ethertype(),
            //     ethernet.packet().len()
            // ),
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

            std::thread::sleep(std::time::Duration::from_millis(10));

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
                                );
                                continue;
                            }
                        }
                    }
                    Self::handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
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

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Component for PacketDump {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }

        // -- active interface set
        if let Action::ActiveInterface(ref interface) = action {
            let mut was_none = false;
            if self.active_interface == None {
                was_none = true;
            }
            self.active_interface = Some(interface.clone());
            if was_none {
                self.start_loop();
            }
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        // let rect = Rect::new(20, 0, f.size().width - 20, 1);
        // let title = format!(" hovno");
        // f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}

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
    ipv4::Ipv4Packet,
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
                target_ip: header.get_target_proto_addr() 
            })).unwrap();
        }
    }

    fn handle_ethernet_frame(
        interface: &NetworkInterface,
        ethernet: &EthernetPacket,
        tx: UnboundedSender<Action>,
    ) {
        let interface_name = &interface.name[..];
        match ethernet.get_ethertype() {
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

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ipnetwork::Ipv4Network;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};
use pnet::util::MacAddr;
use ratatui::{prelude::*, widgets::*};
use tokio::{
    sync::mpsc::{self, UnboundedSender, UnboundedReceiver},
    task::{self, JoinHandle},
};

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
};

// pub struct PacketDump<'a> {
pub struct PacketDump {
    loop_task: JoinHandle<()>,
    should_quit: bool,
    action_tx: Option<UnboundedSender<Action>>,
    loop_tx: Option<UnboundedSender<Action>>,
    // action_rx: Option<&'a UnboundedReceiver<Action>>,
    // action_rx: Option<UnboundedReceiver<Action>>,
    active_interface: Option<NetworkInterface>,
    ips: Vec<Ipv4Addr>,
}

// impl PacketDump<'_> {
impl PacketDump {
    pub fn new() -> Self {
        Self {
            loop_task: tokio::spawn(async {}),
            should_quit: false,
            action_tx: None,
            loop_tx: None,
            // action_rx: None,
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

    fn start_loop(&mut self) {
        // let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
        // self.loop_tx = Some(action_tx);

        // let active_interface = self.active_interface.clone().unwrap();

        // self.loop_task = tokio::spawn(async move {
        //     let (_, mut receiver) =
        //         match pnet::datalink::channel(&active_interface, Default::default()) {
        //             Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        //             Ok(_) => panic!("Unknown channel type"),
        //             Err(e) => panic!("Error happened {}", e),
        //         };
        //     // let mut ips = vec![];
        //     loop {
        //         let buf = receiver.next().unwrap();
        //         let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..])
        //             .unwrap();
        //         if arp.get_sender_proto_addr() == target_ip
        //             // && arp.get_target_hw_addr() == interface.mac.unwrap()
        //         {
        //             // println!("Received reply");
        //             // return arp.get_sender_hw_addr();
        //         }

        //         // let mut should_quit = false;
        //         // while let Ok(action) = action_rx.try_recv() {
        //         //     match action {
        //         //         Action::ArpSend(ip) => {
        //         //             ips.push(ip);
        //         //         }
        //         //         // Action::Quit => {
        //         //         //     should_quit = true;
        //         //         // }
        //         //         _ => {}
        //         //     }
        //         //     // if action == Action::Quit {
        //         //     //     should_quit = true;
        //         //     // }
        //         //     // if action == Action::ArpSend(ip) {
        //         //     //     ips.push(ip);
        //         //     // }
        //         // }
        //         // println!("{}", ips.len());
        //         // if should_quit {
        //         //     println!("QQUIT PICO");
        //         //     break;
        //         // }

        //         tokio::time::sleep(Duration::from_millis(1)).await;
        //         tokio::task::yield_now().await;
        //     }
        // });
    }

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }
}

// impl Default for PacketDump<'a> {
impl Default for PacketDump {
    fn default() -> Self {
        Self::new()
    }
}

// impl Component for PacketDump<'a> {
impl Component for PacketDump {
    // fn init(&mut self, area: Rect) -> Result<()> {
    //     // -- TODO: tokio async green thread infinite loop taking too much CPU
    //     let tx = self.action_tx.clone().unwrap();
    //     let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

    //     if self.loop_created == false {
    //         let active_interface = self.active_interface.clone().unwrap();
    //         self.loop_task = tokio::spawn(async move {
    //             // let active_interface = self.active_interface.clone().unwrap();
    //             let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
    //             let (_, mut receiver) =
    //                 match pnet::datalink::channel(&active_interface, Default::default()) {
    //                     Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
    //                     Ok(_) => panic!("Unknown channel type"),
    //                     Err(e) => panic!("Error happened {}", e),
    //                 };
    //             loop {
    //                 // let buf = receiver.next().unwrap();
    //                 // let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..])
    //                 //     .unwrap();
    //                 // if arp.get_sender_proto_addr() == target_ip
    //                 //     // && arp.get_target_hw_addr() == interface.mac.unwrap()
    //                 // {
    //                 //     println!("Received reply");
    //                 //     return arp.get_sender_hw_addr();
    //                 // }

    //                 let mut should_quit = false;
    //                 while let Ok(action) = action_rx.try_recv() {
    //                     if action == Action::Quit {
    //                         should_quit = true;
    //                     }
    //                 }
    //                 if should_quit {
    //                     break;
    //                 }

    //                 tokio::time::sleep(Duration::from_millis(1)).await;
    //                 tokio::task::yield_now().await;
    //             }
    //         });
    //         self.loop_created = true;
    //     }
    //     Ok(())
    // }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    // fn register_action_reciever(&mut self, ref rx: UnboundedReceiver<Action>) -> Result<()> {
    //     self.action_rx = Some(rx);
    //     Ok(())
    // }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }

        if let Action::ActiveInterface(ref interface) = action {
            self.active_interface = Some(interface.clone());
            // self.start_loop();
        }

        // if let Action::ArpSend(ip) = action {
        //     self.send_arp(ip);
        // }

        // if let Action::Quit = action {
        //     println!("MASLO ABORT");
        //     self.should_quit = true;
        //     // self.loop_task.abort();
        // }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        // let rect = Rect::new(20, 0, f.size().width - 20, 1);
        // let title = format!(" hovno");
        // f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}

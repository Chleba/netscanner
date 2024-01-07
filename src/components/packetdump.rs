use std::{collections::HashMap, time::Duration};

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{prelude::*, widgets::*};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
};

pub struct PacketDump {
    loop_created: bool,
    action_tx: Option<UnboundedSender<Action>>,
    loop_task: JoinHandle<()>,
    should_quit: bool,
}

impl PacketDump {
    pub fn new() -> Self {
        Self {
            loop_created: false,
            action_tx: None,
            loop_task: tokio::spawn(async {}),
            should_quit: false,
        }
    }

    fn send_arp() {
        // //
        // let mut ethernet_buffer = [0u8; 42];
        // let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        // ethernet_packet.set_destination(MacAddr::broadcast());
        // ethernet_packet.set_source(interface.mac.unwrap());
        // ethernet_packet.set_ethertype(EtherTypes::Arp);

        // let mut arp_buffer = [0u8; 28];
        // let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        // arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        // arp_packet.set_protocol_type(EtherTypes::Ipv4);
        // arp_packet.set_hw_addr_len(6);
        // arp_packet.set_proto_addr_len(4);
        // arp_packet.set_operation(ArpOperations::Request);
        // arp_packet.set_sender_hw_addr(interface.mac.unwrap());
        // arp_packet.set_sender_proto_addr(source_ip);
        // arp_packet.set_target_hw_addr(MacAddr::zero());
        // arp_packet.set_target_proto_addr(target_ip);

        // ethernet_packet.set_payload(arp_packet.packet_mut());
    }

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Default for PacketDump {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for PacketDump {
    fn init(&mut self, area: Rect) -> Result<()> {
        // let tx = self.action_tx.clone().unwrap();
        // let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

        // if self.loop_created == false {
        //     self.loop_task = tokio::spawn(async move {
        //         let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
        //         loop {
        //             let mut should_quit = false;
        //             while let Ok(action) = action_rx.try_recv() {
        //                 if action == Action::Quit {
        //                     should_quit = true;
        //                 }
        //             }
        //             if should_quit {
        //                 break;
        //             }
        //             tokio::task::yield_now().await;
        //         }
        //     });
        //     self.loop_created = true;
        // }
        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }

        if let Action::Quit = action {
            println!("MASLO ABORT");
            self.should_quit = true;
            // self.loop_task.abort();
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let rect = Rect::new(20, 0, f.size().width - 20, 1);
        let title = format!(" hovno");
        f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}

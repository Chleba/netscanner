use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};
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
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::Component;
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    enums::{PortsScanState, TabsEnum},
    layout::get_vertical_layout,
    tui::Frame,
};

const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

pub struct Sniffer {
    active_tab: TabsEnum,
    action_tx: Option<UnboundedSender<Action>>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
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
            spinner_index: 0,
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

    fn previous_in_list(&mut self) {
        // let index = match self.list_state.selected() {
        //     Some(index) => {
        //         if index == 0 {
        //             if self.ip_ports.is_empty() {
        //                 0
        //             } else {
        //                 self.ip_ports.len() - 1
        //             }
        //         } else {
        //             index - 1
        //         }
        //     }
        //     None => 0,
        // };
        // self.list_state.select(Some(index));
        // self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_list(&mut self) {
        // let index = match self.list_state.selected() {
        //     Some(index) => {
        //         let mut s_ip_len = 0;
        //         if !self.ip_ports.is_empty() {
        //             s_ip_len = self.ip_ports.len() - 1;
        //         }
        //         if index >= s_ip_len {
        //             0
        //         } else {
        //             index + 1
        //         }
        //     }
        //     None => 0,
        // };
        // self.list_state.select(Some(index));
        // self.scrollbar_state = self.scrollbar_state.position(index);
    }
}

impl Component for Sniffer {
    fn init(&mut self, area: Size) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            let mut s_index = self.spinner_index + 1;
            s_index %= SPINNER_SYMBOLS.len() - 1;
            self.spinner_index = s_index;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        // if self.active_tab == TabsEnum::Tra {
        //     let layout = get_vertical_layout(area);

        //     let mut list_rect = layout.bottom;
        //     list_rect.y += 1;
        //     list_rect.height -= 1;

        //     // -- LIST
        //     let list = self.make_list();
        //     f.render_stateful_widget(list, list_rect, &mut self.list_state.clone());

        //     // -- SCROLLBAR
        //     let scrollbar = Self::make_scrollbar();
        //     let mut scroll_rect = list_rect;
        //     scroll_rect.y += 1;
        //     scroll_rect.height -= 2;
        //     f.render_stateful_widget(
        //         scrollbar,
        //         scroll_rect.inner(&Margin {
        //             vertical: 1,
        //             horizontal: 1,
        //         }),
        //         &mut self.scrollbar_state,
        //     );
        // }

        Ok(())
    }
}

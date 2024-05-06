use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};
use futures::future::join_all;

use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};

use core::str;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr};
use std::string;
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::Component;
use crate::{
    action::Action,
    components::discovery::ScannedIp,
    enums::TabsEnum,
    mode::Mode,
    tui::Frame,
    layout::get_vertical_layout,
};
use crossterm::event::{KeyCode, KeyEvent};
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

static POOL_SIZE: usize = 32;
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

pub struct Ports {
    active_tab: TabsEnum,
    active_interface: Option<NetworkInterface>,
    action_tx: Option<UnboundedSender<Action>>,
    scanned_ips: Vec<ScannedIp>,
    cidr: Option<Ipv4Cidr>,
    task: JoinHandle<()>,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
}

impl Default for Ports {
    fn default() -> Self {
        Self::new()
    }
}

impl Ports {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            active_interface: None,
            task: tokio::spawn(async {}),
            action_tx: None,
            scanned_ips: Vec::new(),
            cidr: None,
            table_state: TableState::default().with_selected(0),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
        }
    }

    fn set_scrollbar_height(&mut self) {
        let mut ip_len = 0;
        if self.scanned_ips.len() > 0 {
            ip_len = self.scanned_ips.len() - 1;
        }
        self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    fn previous_in_table(&mut self) {
        // let index = match self.table_state.selected() {
        //     Some(index) => {
        //         if index == 0 {
        //             if self.scanned_ips.len() > 0 {
        //                 self.scanned_ips.len() - 1
        //             } else {
        //                 0
        //             }
        //         } else {
        //             index - 1
        //         }
        //     }
        //     None => 0,
        // };
        // self.table_state.select(Some(index));
        // self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_table(&mut self) {
        // let index = match self.table_state.selected() {
        //     Some(index) => {
        //         let mut s_ip_len = 0;
        //         if self.scanned_ips.len() > 0 {
        //             s_ip_len = self.scanned_ips.len() - 1;
        //         }
        //         if index >= s_ip_len {
        //             0
        //         } else {
        //             index + 1
        //         }
        //     }
        //     None => 0,
        // };
        // self.table_state.select(Some(index));
        // self.scrollbar_state = self.scrollbar_state.position(index);
    }

    // fn make_table(
    //     scanned_ips: Vec<ScannedIp>,
    //     cidr: Option<Ipv4Cidr>,
    //     ip_num: i32,
    // ) -> Table<'static> {
    //     let header = Row::new(vec!["ip", "mac", "hostname", "vendor"])
    //         .style(Style::default().fg(Color::Yellow))
    //         .top_margin(1)
    //         .bottom_margin(1);
    //     let mut rows = Vec::new();
    //     let cidr_length = match cidr {
    //         Some(c) => count_ipv4_net_length(c.network_length() as u32),
    //         None => 0,
    //     };

    //     for sip in scanned_ips {
    //         let ip = &sip.ip;
    //         rows.push(Row::new(vec![
    //             Cell::from(Span::styled(
    //                 format!("{ip:<2}"),
    //                 Style::default().fg(Color::Blue),
    //             )),
    //             Cell::from(sip.mac.clone().green()),
    //             Cell::from(sip.hostname.clone()),
    //             Cell::from(sip.vendor.clone().yellow()),
    //         ]));
    //     }

    //     let table = Table::new(
    //         rows,
    //         [
    //             Constraint::Length(16),
    //             Constraint::Length(19),
    //             Constraint::Fill(1),
    //             Constraint::Fill(1),
    //         ],
    //     )
    //     .header(header)
    //     .block(
    //         Block::new()
    //             .title(
    //                 ratatui::widgets::block::Title::from("|Ports|".yellow())
    //                     .position(ratatui::widgets::block::Position::Top)
    //                     .alignment(Alignment::Right),
    //             )
    //             .title(
    //                 ratatui::widgets::block::Title::from(Line::from(vec![
    //                     Span::styled("|", Style::default().fg(Color::Yellow)),
    //                     Span::styled(format!("{}", ip_num), Style::default().fg(Color::Green)),
    //                     Span::styled(
    //                         format!("/{}", cidr_length),
    //                         Style::default().fg(Color::Green),
    //                     ),
    //                     Span::styled(" ip|", Style::default().fg(Color::Yellow)),
    //                 ]))
    //                 .position(ratatui::widgets::block::Position::Top)
    //                 .alignment(Alignment::Left),
    //             )
    //             .title(
    //                 ratatui::widgets::block::Title::from(Line::from(vec![
    //                     Span::styled("|", Style::default().fg(Color::Yellow)),
    //                     String::from(char::from_u32(0x25b2).unwrap_or('>')).red(),
    //                     String::from(char::from_u32(0x25bc).unwrap_or('>')).red(),
    //                     Span::styled("select|", Style::default().fg(Color::Yellow)),
    //                 ]))
    //                 .position(ratatui::widgets::block::Position::Bottom)
    //                 .alignment(Alignment::Left),
    //             )
    //             .title(
    //                 ratatui::widgets::block::Title::from(Line::from(vec![
    //                     Span::styled("|show ", Style::default().fg(Color::Yellow)),
    //                     Span::styled("p", Style::default().fg(Color::Red)),
    //                     Span::styled("ackets|", Style::default().fg(Color::Yellow)),
    //                 ]))
    //                 .position(ratatui::widgets::block::Position::Bottom)
    //                 .alignment(Alignment::Right),
    //             )
    //             .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
    //             .borders(Borders::ALL), // .padding(Padding::new(1, 0, 2, 0)),
    //     )
    //     .highlight_symbol(String::from(char::from_u32(0x25b6).unwrap_or('>')).red())
    //     .column_spacing(1);
    //     table
    // }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        // let s_start = String::from(char::from_u32(0x25b2).unwrap_or('#'));
        // let s_end = String::from(char::from_u32(0x25bc).unwrap_or('#'));
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None);
        scrollbar
    }

    fn make_spinner(&self) -> Span {
        let spinner = SPINNER_SYMBOLS[self.spinner_index];
        Span::styled(
            format!("{spinner}scanning.."),
            Style::default().fg(Color::Yellow),
        )
    }
}

impl Component for Ports {
    fn init(&mut self, area: Rect) -> Result<()> {
        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Ports {
            let layout = get_vertical_layout(area);
            // -- LIST
            let mut list_rect = layout.bottom;
            list_rect.y += 1;
            list_rect.height -= 1;

            // let list = self.make_list();
        }

        // if !self.show_packets {
        //     // let layout = Layout::default()
        //     //     .direction(Direction::Vertical)
        //     //     .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        //     //     .split(area);
        //     let layout = get_vertical_layout(area);

        //     // -- TABLE
        //     // let mut table_rect = layout[1];
        //     let mut table_rect = layout.bottom;
        //     table_rect.y += 1;
        //     table_rect.height -= 1;

        //     let table = Self::make_table(self.scanned_ips.clone(), self.cidr, self.ip_num);
        //     f.render_stateful_widget(table, table_rect, &mut self.table_state.clone());

        //     // -- SCROLLBAR
        //     let scrollbar = Self::make_scrollbar();
        //     let mut scroll_rect = table_rect;
        //     scroll_rect.y += 3;
        //     scroll_rect.height -= 3;
        //     f.render_stateful_widget(
        //         scrollbar,
        //         scroll_rect.inner(&Margin {
        //             vertical: 1,
        //             horizontal: 1,
        //         }),
        //         &mut self.scrollbar_state,
        //     );

        //     // -- ERROR
        //     if self.cidr_error {
        //         let error_rect = Rect::new(table_rect.width - (19 + 41), table_rect.y + 1, 18, 3);
        //         let block = self.make_error();
        //         f.render_widget(block, error_rect);
        //     }

        //     // -- INPUT
        //     let input_size: u16 = INPUT_SIZE as u16;
        //     let input_rect = Rect::new(
        //         table_rect.width - (input_size + 1),
        //         table_rect.y + 1,
        //         input_size,
        //         3,
        //     );
        //     // -- INPUT_SIZE - 3 is offset for border + 1char for cursor
        //     let scroll = self.input.visual_scroll(INPUT_SIZE - 3);
        //     let mut block = self.make_input(scroll);
        //     if self.is_scanning {
        //         block = block.clone().add_modifier(Modifier::DIM);
        //     }
        //     f.render_widget(block, input_rect);
        //     // -- cursor
        //     match self.mode {
        //         Mode::Input => {
        //             f.set_cursor(
        //                 input_rect.x
        //                     + ((self.input.visual_cursor()).max(scroll) - scroll) as u16
        //                     + 1,
        //                 input_rect.y + 1,
        //             );
        //         }
        //         Mode::Normal => {}
        //     }

        //     // -- THROBBER
        //     if self.is_scanning {
        //         let throbber = self.make_spinner();
        //         let throbber_rect = Rect::new(input_rect.x + 1, input_rect.y, 12, 1);
        //         f.render_widget(throbber, throbber_rect);
        //     }
        // }

        Ok(())
    }
}

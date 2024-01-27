use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use dns_lookup::{lookup_addr, lookup_host};
use futures::future::{AbortHandle, Abortable};
use futures::FutureExt;

use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};
use pnet::util::MacAddr;

use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};
use crossterm::event::{KeyCode, KeyEvent};
use mac_oui::Oui;
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

static POOL_SIZE: usize = 32;

struct ScannedIp {
    ip: String,
    mac: String,
    hostname: String,
    vendor: String,
}

pub struct Discovery {
    active_interface: Option<NetworkInterface>,
    action_tx: Option<UnboundedSender<Action>>,
    scanned_ips: Vec<ScannedIp>,
    ip_num: i32,
    input: Input,
    cidr: Option<Ipv4Cidr>,
    cidr_error: bool,
    mode: Mode,
    task: JoinHandle<()>,
    oui: Option<Oui>,
    // arp_tasks: Vec<JoinHandle<_, _>>,
    abortables: Vec<AbortHandle>,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            active_interface: None,
            task: tokio::spawn(async {}),
            action_tx: None,
            scanned_ips: Vec::new(),
            ip_num: 0,
            input: Input::default().with_value(String::from("192.168.1.0/24")),
            cidr: None,
            cidr_error: false,
            mode: Mode::Normal,
            oui: None,
            // arp_tasks: Vec::new(),
            abortables: Vec::new(),
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

        let (mut sender, mut receiver) =
            match pnet::datalink::channel(&active_interface, Default::default()) {
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

        let tx = self.action_tx.clone().unwrap();
        let (abort_handle, abort_reg) = AbortHandle::new_pair();
        self.abortables.push(abort_handle.clone());
        let task = tokio::spawn(Abortable::new(
            async move {
                loop {
                    let buf = receiver.next().unwrap_or_default();
                    if buf.len() >= MutableEthernetPacket::minimum_packet_size() {
                        let arp =
                            ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..])
                                .unwrap();
                        if arp.get_sender_proto_addr() == target_ip
                            && arp.get_target_hw_addr() == active_interface.mac.unwrap()
                        {
                            tx.send(Action::ArpRecieve(target_ip, arp.get_sender_hw_addr()))
                                .unwrap();
                        }
                    }
                    // tokio::task::yield_now().await;
                }
            },
            abort_reg,
        ).boxed());
        // self.arp_tasks.push(task);
        // let abort_handle = abort_handle.clone();
        // let abort_handle = abort_handle.clone();
        let timeout_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            abort_handle.abort();
        });
    }

    fn abort_arp_tasks(&mut self) {
        // for t in &self.arp_tasks {
        //     t.abort();
        // }

        for t in &self.abortables {
            t.abort();
        }
        self.abortables.clear();
    }

    fn set_cidr(&mut self, cidr_str: String) {
        match &cidr_str.parse::<Ipv4Cidr>() {
            Ok(ip_cidr) => {
                self.cidr = Some(*ip_cidr);
                self.scan();
            }
            Err(e) => {
                let tx = self.action_tx.clone().unwrap();
                tx.send(Action::CidrError).unwrap();
            }
        }
    }

    fn get_ips(cidr: Ipv4Cidr) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        for ip in cidr.iter() {
            ips.push(ip.address());
        }
        ips
    }

    fn reset_scan(&mut self) {
        self.scanned_ips.clear();
        self.ip_num = 0;
    }

    fn scan(&mut self) {
        self.reset_scan();

        if let Some(cidr) = self.cidr {
            let tx = self.action_tx.clone().unwrap();
            self.task = tokio::spawn(async move {
                let ips = Self::get_ips(cidr);
                let tx = tx.clone();
                let chunks: Vec<_> = ips.chunks(POOL_SIZE).collect();
                for chunk in chunks {
                    let tasks: Vec<_> = chunk
                        .iter()
                        .map(|&ip| {
                            let tx = tx.clone();
                            let closure = || async move {
                                let client =
                                    Client::new(&Config::default()).expect("Cannot create client");
                                let payload = [0; 56];
                                let mut pinger = client
                                    .pinger(IpAddr::V4(ip), PingIdentifier(random()))
                                    .await;
                                pinger.timeout(Duration::from_secs(2));
                                match pinger.ping(PingSequence(3), &payload).await {
                                    Ok((IcmpPacket::V4(packet), dur)) => {
                                        tx.send(Action::PingIp(packet.get_real_dest().to_string()))
                                            .unwrap_or_default();
                                    }
                                    Ok(_) => {
                                        tx.send(Action::CountIp).unwrap_or_default();
                                    }
                                    Err(_) => {
                                        tx.send(Action::CountIp).unwrap_or_default();
                                    }
                                }
                            };
                            task::spawn(closure())
                        })
                        .collect();

                    for task in tasks {
                        task.await.unwrap();
                    }
                }
            });
        };
    }

    fn process_ip(&mut self, ip: &str) {
        let tx = self.action_tx.clone().unwrap();

        let ipv4: Ipv4Addr = ip.parse().unwrap();
        // self.send_arp(ipv4);

        if let Some(n) = self
            .scanned_ips
            .iter_mut()
            .find(|item| item.ip == ip.to_string())
        {
            let hip: IpAddr = ip.parse().unwrap();
            let host = lookup_addr(&hip).unwrap_or(String::from(""));
            n.hostname = host;
            n.ip = ip.to_string();
        } else {
            let hip: IpAddr = ip.parse().unwrap();
            let host = lookup_addr(&hip).unwrap_or(String::from(""));
            self.scanned_ips.push(ScannedIp {
                ip: ip.to_string(),
                mac: String::from(""),
                hostname: host,
                vendor: String::from(""),
            })
        }
    }

    fn process_mac(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if let Some(n) = self
            .scanned_ips
            .iter_mut()
            .find(|item| item.ip == ip.to_string())
        {
            n.mac = mac.to_string();

            if let Some(oui) = &self.oui {
                let oui_res = oui.lookup_by_mac(&n.mac);
                match oui_res {
                    Ok(e) => {
                        if let Some(oui_res) = e {
                            let cn = oui_res.company_name.clone();
                            n.vendor = cn;
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    pub fn make_ui(&mut self) -> Table {
        let header = Row::new(vec!["ip", "hostname", "mac", "vendor"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
        let mut rows = Vec::new();

        for sip in &self.scanned_ips {
            let ip = &sip.ip;
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    format!("{ip:<2}"),
                    Style::default().fg(Color::Blue),
                )),
                Cell::from(sip.hostname.clone()),
                Cell::from(sip.mac.clone().green()),
                Cell::from(sip.vendor.clone().yellow()),
            ]));
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(25),
                Constraint::Length(20),
                Constraint::Length(25),
            ],
        )
        .header(header)
        .block(
            Block::new()
                .title(
                    ratatui::widgets::block::Title::from("|Discovery|".yellow())
                        .position(ratatui::widgets::block::Position::Top)
                        .alignment(Alignment::Right),
                )
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::styled("|", Style::default().fg(Color::Yellow)),
                        Span::styled(
                            String::from(format!("{}", self.ip_num.to_string())),
                            Style::default().fg(Color::Green),
                        ),
                        Span::styled(" ip scanned|", Style::default().fg(Color::Yellow)),
                    ]))
                    .position(ratatui::widgets::block::Position::Top)
                    .alignment(Alignment::Left),
                )
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .borders(Borders::ALL)
                .padding(Padding::new(1, 0, 2, 0)),
        )
        .highlight_symbol("*")
        .column_spacing(1);
        table
    }

    fn make_input(&mut self, scroll: usize) -> Paragraph {
        // let scroll = self.input.visual_scroll(40);
        let input = Paragraph::new(self.input.value())
            .style(Style::default().fg(Color::Yellow))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(match self.mode {
                        Mode::Input => Style::default().fg(Color::Green),
                        Mode::Normal => Style::default().fg(Color::Rgb(100, 100, 100)),
                    })
                    .title(Line::from(vec![
                        Span::raw("|"),
                        Span::styled(
                            "i",
                            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                        ),
                        Span::styled("nput", Style::default().fg(Color::Gray)),
                        Span::raw("/"),
                        Span::styled(
                            "ESC",
                            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                        ),
                        Span::raw("|"),
                    ]))
                    .title_alignment(Alignment::Right)
                    .title_position(ratatui::widgets::block::Position::Bottom),
            );
        input
    }

    fn make_error(&mut self) -> Paragraph {
        let error = Paragraph::new("CIDR parse error")
            .style(Style::default().fg(Color::Red))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(Color::Red)),
            );
        error
    }
}

impl Component for Discovery {
    fn init(&mut self, area: Rect) -> Result<()> {
        if self.cidr == None {
            let cidr_range = "192.168.1.0/24";
            match cidr_range.parse::<Ipv4Cidr>() {
                Ok(ip_cidr) => {
                    self.cidr = Some(ip_cidr);
                    // self.scan();
                }
                Err(e) => {
                    // eprintln!("Error parsing CIDR range: {}", e);
                }
            }
        }

        match Oui::default() {
            Ok(s) => self.oui = Some(s),
            Err(_) => self.oui = None,
        }

        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        let action = match self.mode {
            Mode::Normal => return Ok(None),
            Mode::Input => match key.code {
                KeyCode::Enter => {
                    if let Some(sender) = &self.action_tx {
                        self.set_cidr(self.input.value().to_string());
                    }
                    Action::ModeChange(Mode::Normal)
                }
                _ => {
                    self.input.handle_event(&crossterm::event::Event::Key(key));
                    return Ok(None);
                }
            },
        };
        Ok(Some(action))
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // -- custom actions
        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
            self.ip_num += 1;
        }
        // -- count IPs
        if let Action::CountIp = action {
            self.ip_num += 1;
        }
        // -- CIDR error
        if let Action::CidrError = action {
            self.cidr_error = true;
        }
        // -- active interface
        if let Action::ActiveInterface(ref interface) = action {
            let intf = interface.clone();
            // -- first time scan after setting of interface
            if self.active_interface == None {
                self.scan();
            }
            self.active_interface = Some(intf);
        }
        // if let Action::Abort = action {
        //     self.abort_arp_tasks();
        // }
        // -- quit
        if let Action::Quit = action {
            self.abort_arp_tasks();
        }
        // -- ARP packet recieved
        if let Action::ArpRecieve(target_ip, mac) = action {
            self.process_mac(target_ip, mac);
        }
        // -- MODE CHANGE
        if let Action::ModeChange(mode) = action {
            if mode == Mode::Input {
                // self.input.reset();
                self.cidr_error = false;
            }
            self.mode = mode;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // -- TABLE
        let mut table_rect = layout[1].clone();
        table_rect.y += 1;
        table_rect.height -= 1;
        let block = self.make_ui();
        f.render_widget(block, table_rect);
        // f.render_stateful_widget(block, table_rect);

        // -- ERROR
        if self.cidr_error == true {
            let error_rect = Rect::new(table_rect.width - (19 + 41), table_rect.y + 1, 18, 3);
            let block = self.make_error();
            f.render_widget(block, error_rect);
        }

        // -- INPUT
        let input_rect = Rect::new(table_rect.width - 41, table_rect.y + 1, 40, 3);
        let scroll = self.input.visual_scroll(40);
        let block = self.make_input(scroll);
        f.render_widget(block, input_rect);
        // -- cursor
        match self.mode {
            Mode::Input => {
                f.set_cursor(
                    input_rect.x + ((self.input.visual_cursor()).max(scroll) - scroll) as u16 + 1,
                    input_rect.y + 1,
                );
            }
            Mode::Normal => {}
        }

        Ok(())
    }
}

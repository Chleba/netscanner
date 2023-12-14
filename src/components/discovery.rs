use chrono::Timelike;
use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use dns_lookup::{lookup_addr, lookup_host};
use futures::future::join_all;
use itertools::Position;
use pnet::datalink::{self, NetworkInterface};
use ratatui::{prelude::*, widgets::*};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};
use crossterm::event::{KeyCode, KeyEvent};
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

struct ScannedIp {
    ip: String,
    mac: String,
    hostname: String,
    vendor: String,
}

pub struct Discovery {
    action_tx: Option<UnboundedSender<Action>>,
    last_update_time: Instant,
    scanning: bool,
    scanned_ips: Vec<ScannedIp>,
    ips_to_scan: Vec<Ipv4Addr>,
    input: Input,
    cidr: Option<Ipv4Cidr>,
    cidr_error: bool,
    mode: Mode,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            last_update_time: Instant::now(),
            scanning: false,
            scanned_ips: Vec::new(),
            ips_to_scan: Vec::new(),
            input: Input::default().with_value(String::from("192.168.1.0/24")),
            cidr: None,
            cidr_error: false,
            mode: Mode::Normal,
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        if self.cidr == None {
            let cidr_range = "192.168.1.0/24";
            match cidr_range.parse::<Ipv4Cidr>() {
                Ok(ip_cidr) => {
                    self.cidr = Some(ip_cidr);
                    self.scan();
                }
                Err(e) => {
                    // eprintln!("Error parsing CIDR range: {}", e);
                }
            }
        }

        Ok(())
    }

    fn set_cidr(&mut self, cidr_str: String) {
        match &cidr_str.parse::<Ipv4Cidr>() {
            Ok(ip_cidr) => {
                self.cidr = Some(*ip_cidr);
                self.scan();
            }
            Err(e) => {
                let tx = self.action_tx.clone().unwrap();
                let _ = tx.send(Action::CidrError);
            }
        }
    }

    fn scan(&mut self) {
        self.scanned_ips.clear();
        if let Some(cidr) = self.cidr {
            let mut tasks = Vec::new();
            for ip in cidr.iter() {
                let ip = ip.address().to_string();
                match ip.parse() {
                    Ok(IpAddr::V4(addr)) => {
                        let tx = self.action_tx.clone().unwrap();
                        tasks.push(tokio::spawn(async move {
                            let client =
                                Client::new(&Config::default()).expect("Cannot create client");
                            let payload = [0; 56];
                            let mut pinger = client
                                .pinger(IpAddr::V4(addr), PingIdentifier(random()))
                                .await;
                            pinger.timeout(Duration::from_secs(1));
                            match pinger.ping(PingSequence(0), &payload).await {
                                Ok((IcmpPacket::V4(packet), dur)) => {
                                    tx.send(Action::PingIp(packet.get_real_dest().to_string()))
                                        .unwrap();
                                }
                                Ok(_) => {}
                                Err(_) => {}
                            }
                        }));

                        // let tx = self.action_tx.clone().unwrap();
                        // tokio::spawn(async move {
                        //     let client =
                        //         Client::new(&Config::default()).expect("Cannot create client");
                        //     let payload = [0; 56];
                        //     let mut pinger = client
                        //         .pinger(IpAddr::V4(addr), PingIdentifier(random()))
                        //         .await;
                        //     pinger.timeout(Duration::from_secs(1));
                        //     match pinger.ping(PingSequence(0), &payload).await {
                        //         Ok((IcmpPacket::V4(packet), dur)) => {
                        //             tx.send(Action::PingIp(packet.get_real_dest().to_string()))
                        //                 .unwrap();
                        //         }
                        //         Ok(_) => {}
                        //         Err(_) => {}
                        //     }
                        // });
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let tx = self.action_tx.clone().unwrap();
                        let _ = tx.send(Action::CidrError);
                    }
                }
            }
            let _ = join_all(tasks);
        };
    }

    fn process_ip(&mut self, ip: &str) {
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
            // let mac = get_mac_address()
            self.scanned_ips.push(ScannedIp {
                ip: ip.to_string(),
                mac: String::from(""),
                hostname: host,
                vendor: String::from(""),
            })
        }
    }

    pub fn make_ui(&mut self) -> Table {
        let header = Row::new(vec!["ip", "hostname"])
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
                // Cell::from(""),
                Cell::from(sip.hostname.clone()),
                // Cell::from(""),
                // Cell::from(""),
            ]));
        }

        let table = Table::new(rows)
            .header(header)
            .block(
                Block::default()
                    .title("|Discovery|")
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .title_style(Style::default().fg(Color::Yellow))
                    .title_alignment(Alignment::Right)
                    .borders(Borders::ALL)
                    .padding(Padding::new(1, 0, 1, 0)),
            )
            .widths(&[
                Constraint::Length(16),
                // Constraint::Length(18),
                Constraint::Length(25),
                // Constraint::Length(35),
                // Constraint::Length(25),
            ])
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
        if let Action::Tick = action {
            self.app_tick()?
        }
        // -- custom actions
        if let Action::PingIp(ref ip) = action {
            self.process_ip(ip);
        }

        if let Action::CidrError = action {
            self.cidr_error = true;
        }

        if let Action::ModeChange(mode) = action {
            if mode == Mode::Input {
                self.input.reset();
                self.cidr_error = false;
            }
            self.mode = mode;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // -- TABLE
        let mut table_rect = layout[1].clone();
        table_rect.y += 1;
        table_rect.height -= 1;
        let block = self.make_ui();
        f.render_widget(block, table_rect);

        // -- ERROR
        if self.cidr_error == true {
            let error_rect = Rect::new(table_rect.width - 19, table_rect.y + 4, 18, 3);
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

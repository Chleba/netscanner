use ipnetwork::IpNetwork;
// use itertools::Itertools;
use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;
use std::time::Instant;

use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};

pub struct Interfaces {
    action_tx: Option<UnboundedSender<Action>>,
    interfaces: Vec<NetworkInterface>,
    last_update_time: Instant,
    active_interface: Option<NetworkInterface>,
}

impl Default for Interfaces {
    fn default() -> Self {
        Self::new()
    }
}

impl Interfaces {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            interfaces: Vec::new(),
            last_update_time: Instant::now(),
            active_interface: None,
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let elapsed = (now - self.last_update_time).as_secs_f64();

        if self.interfaces.len() == 0 || elapsed > 5.0 {
            self.last_update_time = now;
            self.interfaces.clear();
            let interfaces = datalink::interfaces();
            for intf in &interfaces {
                // -- get active interface with non-local IP
                if intf.is_up() && !intf.ips.is_empty() {
                    for ip in &intf.ips {
                        if ip.is_ipv4() && ip.ip().to_string() != "127.0.0.1" {
                            if self.active_interface != Some(intf.clone()) {
                                self.active_interface = Some(intf.clone());

                                let tx = self.action_tx.clone().unwrap();
                                tx.send(Action::ActiveInterface(intf.clone())).unwrap();
                            }
                        }
                    }
                }

                // -- store interfaces into a vec
                self.interfaces.push(intf.clone());
            }

            // -- TODO not working, dunno why the fuck not!!!
            // let localhost: IpNetwork = "127.0.0.1".parse().unwrap();
            // let localhost: IpAddr = "127.0.0.1".parse().unwrap();
            // self.active_interface = interfaces
            //     .iter()
            //     // .find(|e| e.is_up() && !e.ips.is_empty() && !e.ips.iter().contains(&localhost))
            //     .find(|e| e.is_up() && !e.ips.is_empty() && !e.ips.contains(&localhost))
            //     .cloned();
        }
        Ok(())
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["", "name", "mac", "ipv4", "ipv6"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
        let mut rows = Vec::new();
        for w in &self.interfaces {
            let mut active = String::from("");
            if let Some(si) = &self.active_interface {
                if si == w {
                    active = String::from("*");
                }
            }
            let name = w.name.clone();
            let mac = w.mac.unwrap().to_string();
            let ipv4: Vec<Line> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv4())
                .cloned()
                .map(|ip| {
                    let ip_str = ip.ip().to_string();
                    Line::from(vec![Span::styled(
                        format!("{ip_str:<2}"),
                        Style::default().fg(Color::Blue),
                    )])
                })
                .collect();
            let ipv6: Vec<Span> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv6())
                .cloned()
                .map(|ip| Span::from(ip.ip().to_string()))
                .collect();

            let mut row_height = 1;
            if ipv4.len() > 1 {
                row_height = ipv4.clone().len() as u16;
            }
            rows.push(
                Row::new(vec![
                    Cell::from(Span::styled(
                        format!("{active:<1}"),
                        Style::default().fg(Color::Red),
                    )),
                    Cell::from(Span::styled(
                        format!("{name:<2}"),
                        Style::default().fg(Color::Green),
                    )),
                    Cell::from(mac),
                    Cell::from(ipv4.clone()),
                    Cell::from(vec![Line::from(ipv6)]),
                ])
                .height(row_height), // .bottom_margin((ipv4.len()) as u16)
            );
        }

        let table = Table::new(rows)
            .header(header)
            .block(
                Block::default()
                    .title("|Interfaces|")
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .title_style(Style::default().fg(Color::Yellow))
                    .title_alignment(Alignment::Right)
                    .borders(Borders::ALL)
                    .padding(Padding::new(1, 0, 1, 0)),
            )
            .widths(&[
                Constraint::Length(1),
                Constraint::Length(8),
                Constraint::Length(18),
                Constraint::Length(14),
                Constraint::Length(25),
            ])
            .column_spacing(1);
        table
    }
}

impl Component for Interfaces {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);
        let rect = Rect::new(area.width / 2, 1, area.width / 2, layout[0].height);

        let block = self.make_table();
        f.render_widget(block, rect);

        Ok(())
    }
}

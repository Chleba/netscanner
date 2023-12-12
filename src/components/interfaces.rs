use pnet::datalink::{self, NetworkInterface};
use std::time::Instant;

use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, tui::Frame};

pub struct Interfaces {
    pub action_tx: Option<UnboundedSender<Action>>,
    pub interfaces: Vec<NetworkInterface>,
    pub scan_start_time: Instant,
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
            scan_start_time: Instant::now(),
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let elapsed = (now - self.scan_start_time).as_secs_f64();

        if self.interfaces.len() == 0 || elapsed > 5.0 {
            self.scan_start_time = now;
            self.interfaces.clear();
            let interfaces = datalink::interfaces();
            for intf in interfaces {
                self.interfaces.push(intf);
            }
        }
        Ok(())
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["name", "mac", "ipv4", "ipv6"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
        let mut rows = Vec::new();
        for w in &self.interfaces {
            let name = w.name.clone();
            let mac = w.mac.unwrap().to_string();
            let ipv4: Vec<Line> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv4())
                .cloned()
                .map(|ip| {
                    let ip_str = ip.ip().to_string();
                    Line::from(vec![Span::styled(format!("{ip_str:<2}"), Style::default().fg(Color::Blue))])
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
        let rect = Rect::new(area.width / 2, 1, area.width / 2, area.height / 2);

        let block = self.make_table();
        f.render_widget(block, rect);

        Ok(())
    }
}

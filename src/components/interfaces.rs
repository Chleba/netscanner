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
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        if self.interfaces.len() == 0 {
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
            let ipv4: Vec<Span> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv4())
                .cloned()
                .map(|ip| Span::from(ip.ip().to_string()))
                .collect();
            let ipv6: Vec<Span> = w
                .ips
                .iter()
                .filter(|f| f.is_ipv6())
                .cloned()
                .map(|ip| Span::from(ip.ip().to_string()))
                .collect();

            // let signal = format!("({}){}", w.signal, gauge);
            // let color = (percent * (COLORS_SIGNAL.len() as f32)) as usize;
            // let ssid = w.ssid.clone();

            rows.push(Row::new(vec![
                Cell::from(name),
                Cell::from(mac),
                Cell::from(vec![Line::from(ipv4)]),
                Cell::from(vec![Line::from(ipv6)]),
            ]));
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
        let rect = Rect::new(area.width / 2, 1, area.width / 2, area.height / 4);
        let block = self.make_table();
        f.render_widget(block, rect);

        // f.render_widget(
        //     Paragraph::new(" Network scanner").block(
        //         Block::default()
        //             .borders(Borders::ALL)
        //             .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
        //             .title_style(Style::default().fg(Color::Yellow))
        //             .title_alignment(Alignment::Right)
        //             .title("|Interfaces|"),
        //     ),
        //     rect,
        // );
        Ok(())
    }
}

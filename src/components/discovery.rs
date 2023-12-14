use chrono::Timelike;
use color_eyre::eyre::Result;
use itertools::Position;
use pnet::datalink::{self, NetworkInterface};
use ratatui::{prelude::*, widgets::*};
use std::collections::HashMap;
use std::process::{Command, Output};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};
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
    scanned_ips: Vec<ScannedIp>,
    input: Input,
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
            scanned_ips: Vec::new(),
            input: Input::default(),
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn make_ui(&mut self) -> Table {
        let header = Row::new(vec!["ip", "mac", "hostname", "vendor"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
        let mut rows = Vec::new();
        // for w in &self.interfaces {
        //     let name = w.name.clone();
        //     let mac = w.mac.unwrap().to_string();
        //     let ipv4: Vec<Line> = w
        //         .ips
        //         .iter()
        //         .filter(|f| f.is_ipv4())
        //         .cloned()
        //         .map(|ip| {
        //             let ip_str = ip.ip().to_string();
        //             Line::from(vec![Span::styled(
        //                 format!("{ip_str:<2}"),
        //                 Style::default().fg(Color::Blue),
        //             )])
        //         })
        //         .collect();
        //     let ipv6: Vec<Span> = w
        //         .ips
        //         .iter()
        //         .filter(|f| f.is_ipv6())
        //         .cloned()
        //         .map(|ip| Span::from(ip.ip().to_string()))
        //         .collect();

        //     let mut row_height = 1;
        //     if ipv4.len() > 1 {
        //         row_height = ipv4.clone().len() as u16;
        //     }
        //     rows.push(
        //         Row::new(vec![
        //             Cell::from(Span::styled(
        //                 format!("{name:<2}"),
        //                 Style::default().fg(Color::Green),
        //             )),
        //             Cell::from(mac),
        //             Cell::from(ipv4.clone()),
        //             Cell::from(vec![Line::from(ipv6)]),
        //         ])
        //         .height(row_height), // .bottom_margin((ipv4.len()) as u16)
        //     );
        // }

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
                Constraint::Length(8),
                Constraint::Length(18),
                Constraint::Length(14),
                Constraint::Length(25),
            ])
            .column_spacing(1);
        table
    }

    fn make_input(&mut self) -> Paragraph {
        let scroll = self.input.visual_scroll(40);
        let input = Paragraph::new(self.input.value())
            // .style(match self.mode {
            //     Mode::Insert => Style::default().fg(Color::Yellow),
            //     _ => Style::default(),
            // })
            .style(Style::default().fg(Color::Yellow))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
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
}

impl Component for Discovery {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }
        // -- custom actions
        // if let Action::Scan(nets) = action {
        //     self.parse_char_data(&nets);
        // }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        let mut table_rect = layout[1].clone();
        table_rect.y += 1;
        table_rect.height -= 1;

        let input_rect = Rect::new(table_rect.width-41, table_rect.y+1, 40, 3);

        let block = self.make_ui();
        f.render_widget(block, table_rect);

        let block = self.make_input();
        f.render_widget(block, input_rect);

        Ok(())
    }
}

use chrono::{DateTime, Utc};
use itertools::Itertools;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc::UnboundedSender;
use tokio_wifiscanner::Wifi;

use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};

use super::Component;
use crate::{action::Action, tui::Frame};

#[derive(Debug, PartialEq, Clone)]
pub struct WifiInfo {
    time: DateTime<Utc>,
    ssid: String,
    channel: u8,
    signal: f32,
    mac: String,
}

pub struct WifiScan {
    pub action_tx: Option<UnboundedSender<Action>>,
    pub scan_start_time: Instant,
    pub wifis: Vec<WifiInfo>,
}

impl Default for WifiScan {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiScan {
    pub fn new() -> Self {
        Self {
            scan_start_time: Instant::now(),
            wifis: Vec::new(),
            action_tx: None,
        }
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["UTC", "ssid", "channel", "mac", "signal"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(0);
        let mut rows = Vec::new();
        for w in &self.wifis {
            // let gauge = Gauge::default()
            //   .block(Block::default())
            //   .gauge_style(Style::default().fg(Color::White).bg(Color::Black))
            //   .percent(20);

            let max_dbm: f32 = -30.0;
            let min_dbm: f32 = -90.0;
            let s_clamp = w.signal.max(min_dbm).min(max_dbm);
            let percent = ((s_clamp - min_dbm) / (max_dbm - min_dbm)).clamp(0.0, 1.0);

            let p = (percent * 10.0) as usize;
            let gauge: String = std::iter::repeat(char::from_u32(0x25a8).unwrap_or('#'))
                .take(p)
                .collect();

            let signal = format!("({}){}", w.signal, gauge);
            let colors = vec![
                Style::default().fg(Color::Red),
                Style::default().fg(Color::LightRed),
                Style::default().fg(Color::Yellow),
                Style::default().fg(Color::LightMagenta),
                Style::default().fg(Color::Magenta),
                Style::default().fg(Color::LightGreen),
                Style::default().fg(Color::Green),
            ];
            let color = (percent * ((colors.len() - 1) as f32)) as usize;
            let signal = format!("({}){}", w.signal, gauge);

            rows.push(Row::new(vec![
                Cell::from(w.time.format("%H:%M:%S").to_string()),
                Cell::from(w.ssid.clone()),
                Cell::from(w.channel.to_string()),
                Cell::from(w.mac.clone()),
                Cell::from(Span::styled(format!("{signal:<2}"), colors[color])),
            ]));
        }

        let table = Table::new(rows)
            .header(header)
            .block(
                Block::default()
                    .title("|WiFi Networks|")
                    .borders(Borders::ALL),
            )
            .widths(&[
                Constraint::Length(8),
                Constraint::Length(14),
                Constraint::Length(7),
                Constraint::Length(18),
                Constraint::Length(25),
            ])
            .column_spacing(1);
        table
    }

    pub fn scan(&mut self) {
        let tx = self.action_tx.clone().unwrap();
        tokio::spawn(async move {
            let networks = tokio_wifiscanner::scan().await;
            match networks {
                Ok(nets) => {
                    let mut wifi_nets: Vec<WifiInfo> = Vec::new();
                    let now = Utc::now();
                    for w in nets {
                        if let Some(n) = wifi_nets.iter_mut().find(|item| item.ssid == w.ssid) {
                            let signal: f32 = w.signal_level.parse().unwrap_or(-100.00);
                            if n.signal < signal {
                                n.signal = signal;
                                n.mac = w.mac.clone();
                                let channel = w.channel.parse::<u8>().unwrap_or(0);
                                n.channel = channel;
                            }
                        } else {
                            wifi_nets.push(WifiInfo {
                                time: now,
                                ssid: w.ssid.clone(),
                                channel: w.channel.parse::<u8>().unwrap_or(0),
                                signal: w.signal_level.parse::<f32>().unwrap_or(-100.00),
                                mac: w.mac.clone(),
                            });
                        }
                    }
                    tx.send(Action::Scan(wifi_nets)).unwrap();
                }
                Err(_e) => (),
            };
        });
    }

    fn app_tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let elapsed = (now - self.scan_start_time).as_secs_f64();

        if elapsed > 1.5 {
            self.scan_start_time = now;
            self.scan();
        }
        Ok(())
    }

    fn render_tick(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Component for WifiScan {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        };
        if let Action::Render = action {
            self.render_tick()?
        };

        // -- custom actions
        if let Action::Scan(nets) = action {
            self.wifis = nets;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, rect: Rect) -> Result<()> {
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(f.size());

        let mut rect = rects[0];
        rect.y = 1;

        let block = self.make_table();

        // // -- LIST
        // let mut logs: Vec<ListItem> = Vec::new();
        // for w in &self.wifis {
        //   let now = w.time;
        //   let ssid = w.ssid.clone();
        //   let signal = w.signal;
        //   let mac = w.mac.clone();
        //   let channel = w.channel;
        //   let content = vec![
        //     Line::from("-".repeat(rect.width as usize)),
        //     Line::from(vec![
        //       Span::styled(format!("{ssid:<2} "), Style::default()),
        //       Span::styled(format!("{mac:<2} "), Style::default()),
        //       Span::styled(format!("{channel:<2} "), Style::default()),
        //       Span::styled(format!("{signal:<2} "), Style::default()),
        //       // Span::raw(w.signal_level.clone()),
        //       // Span::raw(w.channel.clone()),
        //       // Span::raw(w.mac.clone()),
        //     ]),
        //     Line::from(now.to_rfc3339()),
        //     // Line::from(String::from(&self.wifis.len())),
        //   ];
        //   logs.push(ListItem::new(content));
        // }
        // let block = List::new(logs).block(Block::default().borders(Borders::ALL).title("[Wifi Networks]"));

        // // -- TABLE
        // let mut items: Vec<Row> = Vec::new();
        // for w in &self.wifis {
        //     // println!("{}", w.ssid);
        //   let cells = vec![Cell::from(w.ssid.clone()), Cell::from(w.signal_level.clone())];
        //   items.push(Row::new(cells).height(1));
        // }
        // // println!("{:?}", items);
        // let block = Table::new(items).block(Block::default().title("[Wifi Networks]").borders(Borders::ALL));

        f.render_widget(block, rect);
        Ok(())
    }
}

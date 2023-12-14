use chrono::{DateTime, Timelike, Utc};
use config::Source;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;
use tokio_wifiscanner::Wifi;

use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};

#[derive(Debug, PartialEq, Clone)]
pub struct WifiInfo {
    pub time: DateTime<Utc>,
    pub ssid: String,
    pub channel: u8,
    pub signal: f32,
    pub mac: String,
    pub color: Color,
}

impl WifiInfo {
    fn copy_values(&mut self, net: WifiInfo) {
        self.time = net.time;
        self.ssid = net.ssid;
        self.channel = net.channel;
        self.signal = net.signal;
        self.mac = net.mac;
    }
}

pub struct WifiScan {
    pub action_tx: Option<UnboundedSender<Action>>,
    pub scan_start_time: Instant,
    pub wifis: Vec<WifiInfo>,
    pub signal_tick: [f64; 2],
    // pub mode: Mode,
}

impl Default for WifiScan {
    fn default() -> Self {
        Self::new()
    }
}

const COLORS_SIGNAL: [Color; 7] = [
    Color::Red,
    Color::LightRed,
    Color::LightMagenta,
    Color::Magenta,
    Color::Yellow,
    Color::LightGreen,
    Color::Green,
];

const COLORS_NAMES: [Color; 8] = [
    Color::Yellow,
    Color::Red,
    Color::Green,
    Color::Blue,
    Color::Gray,
    Color::Cyan,
    Color::White,
    Color::Magenta,
];

impl WifiScan {
    pub fn new() -> Self {
        Self {
            scan_start_time: Instant::now(),
            wifis: Vec::new(),
            action_tx: None,
            signal_tick: [0.0, 40.0],
            // mode: Mode::Networks,
        }
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["UTC", "ssid", "ch", "mac", "signal"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
        let mut rows = Vec::new();
        for w in &self.wifis {
            let max_dbm: f32 = -30.0;
            let min_dbm: f32 = -90.0;
            let s_clamp = w.signal.max(min_dbm).min(max_dbm);
            let percent = ((s_clamp - min_dbm) / (max_dbm - min_dbm)).clamp(0.0, 1.0);

            let p = (percent * 10.0) as usize;
            let gauge: String = std::iter::repeat(char::from_u32(0x25a8).unwrap_or('#'))
                .take(p)
                .collect();

            let signal = format!("({}){}", w.signal, gauge);
            let color = (percent * ((COLORS_SIGNAL.len() - 1) as f32)) as usize;
            let ssid = w.ssid.clone();
            let mut signal_span = Span::from("");
            if w.signal < 0.0 {
                signal_span = Span::styled(
                    format!("{signal:<2}"),
                    Style::default().fg(COLORS_SIGNAL[color]),
                );
            }

            rows.push(Row::new(vec![
                Cell::from(w.time.format("%H:%M:%S").to_string()),
                Cell::from(Span::styled(
                    format!("{ssid:<2}"),
                    Style::default().fg(w.color.clone()),
                )),
                Cell::from(w.channel.to_string()),
                Cell::from(w.mac.clone()),
                Cell::from(signal_span),
            ]));
        }

        let table = Table::new(rows)
            .header(header)
            .block(
                Block::default()
                    .title("|WiFi Networks|")
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .title_style(Style::default().fg(Color::Yellow))
                    .title_alignment(Alignment::Right)
                    .borders(Borders::ALL)
                    .padding(Padding::new(1, 0, 1, 0)),
            )
            .widths(&[
                Constraint::Length(8),
                Constraint::Length(11),
                Constraint::Length(4),
                Constraint::Length(17),
                Constraint::Length(18),
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
                                color: COLORS_NAMES[wifi_nets.len()],
                            });
                        }
                    }
                    tx.send(Action::Scan(wifi_nets)).unwrap();
                }
                Err(_e) => (),
            };
        });
    }

    fn parse_networks_data(&mut self, nets: &Vec<WifiInfo>) {
        // -- clear signal values
        self.wifis.iter_mut().for_each(|item| {
            item.signal = 0.0;
        });
        // -- add or update wifi info
        for w in nets {
            if let Some(n) = self.wifis.iter_mut().find(|item| item.ssid == w.ssid) {
                n.copy_values(w.clone());
            } else {
                self.wifis.push(w.clone());
            }
        }
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
            self.parse_networks_data(&nets);
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);
        let table_rect = Rect::new(0, 1, area.width/2, layout[0].height);

        let block = self.make_table();
        f.render_widget(block, table_rect);

        Ok(())
    }
}

use chrono::{DateTime, Local};
use std::time::Instant;
use tokio::sync::mpsc::Sender;

use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};

use super::Component;
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    layout::{get_horizontal_layout, get_vertical_layout},
    tui::Frame,
};

#[derive(Debug, PartialEq, Clone)]
pub struct WifiInfo {
    pub time: DateTime<Local>,
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
    pub action_tx: Option<Sender<Action>>,
    pub scan_start_time: Instant,
    pub wifis: Vec<WifiInfo>,
    pub signal_tick: [f64; 2],
    show_graph: bool,
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

const COLORS_NAMES: [Color; 14] = [
    Color::Rgb(244, 67, 54),
    Color::Rgb(233, 30, 99),
    Color::Rgb(156, 39, 176),
    Color::Rgb(103, 58, 183),
    Color::Rgb(63, 81, 184),
    Color::Rgb(3, 169, 244),
    Color::Rgb(0, 150, 136),
    Color::Rgb(255, 235, 59),
    Color::Rgb(255, 152, 0),
    Color::Rgb(255, 87, 34),
    Color::Rgb(121, 85, 72),
    Color::Rgb(158, 158, 158),
    Color::Rgb(96, 125, 139),
    Color::White,
];

const MIN_DBM: f32 = -100.0;
const MAX_DBM: f32 = -1.0;

impl WifiScan {
    pub fn new() -> Self {
        Self {
            show_graph: false,
            scan_start_time: Instant::now(),
            wifis: Vec::new(),
            action_tx: None,
            signal_tick: [0.0, 40.0],
        }
    }

    fn make_table(&mut self) -> Table<'_> {
        let header = Row::new(vec!["time", "ssid", "ch", "mac", "signal"])
            .style(Style::default().fg(Color::Yellow));
        // .bottom_margin(1);
        let mut rows = Vec::new();
        for w in &self.wifis {
            let s_clamp = w.signal.clamp(MIN_DBM, MAX_DBM);
            let percent = ((s_clamp - MIN_DBM) / (MAX_DBM - MIN_DBM)).clamp(0.0, 1.0);

            let p = (percent * 10.0) as usize;
            let gauge: String = std::iter::repeat_n(char::from_u32(0x25a8).unwrap_or('#'), p)
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
                    Style::default().fg(w.color),
                )),
                Cell::from(w.channel.to_string()),
                Cell::from(w.mac.clone()),
                Cell::from(signal_span),
            ]));
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(4),
                Constraint::Length(17),
                Constraint::Length(18),
            ],
        )
        .header(header)
        .block(
            Block::new()
                .title(
                    ratatui::widgets::block::Title::from("|WiFi Networks|".yellow())
                        .position(ratatui::widgets::block::Position::Top)
                        .alignment(Alignment::Right),
                )
                .title(
                    ratatui::widgets::block::Title::from(Line::from(vec![
                        Span::styled("|show ", Style::default().fg(Color::Yellow)),
                        Span::styled("g", Style::default().fg(Color::Red)),
                        Span::styled("raph|", Style::default().fg(Color::Yellow)),
                    ]))
                    .position(ratatui::widgets::block::Position::Bottom)
                    .alignment(Alignment::Right),
                )
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .borders(Borders::ALL)
                .border_type(DEFAULT_BORDER_STYLE)
                .padding(Padding::new(1, 0, 1, 0)),
        )
        .column_spacing(1);
        table
    }

    pub fn scan(&mut self) {
        let Some(tx) = self.action_tx.clone() else {
            log::error!("Cannot scan WiFi: action channel not initialized");
            return;
        };
        tokio::spawn(async move {
            let networks = tokio_wifiscanner::scan().await;
            match networks {
                Ok(nets) => {
                    let mut wifi_nets: Vec<WifiInfo> = Vec::new();
                    let now = Local::now();
                    for w in nets {
                        if let Some(n) = wifi_nets.iter_mut().find(|item| item.ssid == w.ssid) {
                            let signal: f32 = w.signal_level.parse().unwrap_or(-100.00);
                            if n.signal < signal {
                                n.signal = signal;
                                n.mac = w.mac;
                                let channel = w.channel.parse::<u8>().unwrap_or(0);
                                n.channel = channel;
                            }
                        } else {
                            wifi_nets.push(WifiInfo {
                                time: now,
                                ssid: w.ssid,
                                channel: w.channel.parse::<u8>().unwrap_or(0),
                                signal: w.signal_level.parse::<f32>().unwrap_or(-100.00),
                                mac: w.mac,
                                color: COLORS_NAMES[wifi_nets.len() % COLORS_NAMES.len()],
                            });
                        }
                    }

                    let t_send = tx.try_send(Action::Scan(wifi_nets));
                    match t_send {
                        Ok(_n) => (),
                        Err(_e) => (),
                    }
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
        // -- sort wifi networks by it's signal strength
        self.wifis
            .sort_by(|a, b| b.signal.partial_cmp(&a.signal).unwrap_or(std::cmp::Ordering::Equal));
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
    fn register_action_handler(&mut self, action_tx: Sender<Action>) -> Result<()> {
        self.action_tx = Some(action_tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        };
        if let Action::Render = action {
            self.render_tick()?
        };
        // -- custom actions
        if let Action::Scan(ref nets) = action {
            self.parse_networks_data(nets);
        }

        if let Action::GraphToggle = action {
            self.show_graph = !self.show_graph;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if !self.show_graph {
            let v_layout = get_vertical_layout(area);
            let h_layout = get_horizontal_layout(area);

            let table_rect =
                Rect::new(h_layout.left.x, 1, h_layout.left.width, v_layout.top.height);

            let block = self.make_table();
            f.render_widget(block, table_rect);
        }

        Ok(())
    }
}

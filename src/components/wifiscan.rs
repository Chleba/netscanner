use chrono::Timelike;
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

#[derive(Debug)]
pub struct WifiDataset {
    ssid: String,
    data: Vec<(f64, f64)>,
}

pub struct WifiScan {
    pub action_tx: Option<UnboundedSender<Action>>,
    pub scan_start_time: Instant,
    pub wifis: Vec<WifiInfo>,
    pub wifi_datasets: Vec<WifiDataset>,
    pub signal_tick: f64,
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
            wifi_datasets: Vec::new(),
            action_tx: None,
            signal_tick: 0.0,
        }
    }

    fn make_table(&mut self) -> Table {
        let header = Row::new(vec!["UTC", "ssid", "channel", "mac", "signal"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1);
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
                Style::default().fg(Color::LightMagenta),
                Style::default().fg(Color::Magenta),
                Style::default().fg(Color::Yellow),
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

    pub fn make_chart(&mut self) -> Chart {
        let mut datasets = Vec::new();
        for d in &self.wifi_datasets {
            let dataset = Dataset::default()
                .name(d.ssid.clone())
                .marker(symbols::Marker::Bar)
                .style(Style::default().fg(Color::Red))
                .graph_type(GraphType::Line)
                .data(&d.data);
                // .data(&[(4.0, 10.0), (5.0, 11.0), (6.0, 15.0)]);
            datasets.push(dataset);
        }
        let chart = Chart::new(datasets)
            .block(Block::default().title("Wifi signals").borders(Borders::ALL))
            .y_axis(
                Axis::default()
                    .bounds([0.0, 100.0])
                    .title("signal")
                    .style(Style::default().fg(Color::Yellow)),
            )
            .x_axis(
                Axis::default()
                    // .bounds([2.0, self.signal_tick])
                    .bounds([0.0, 100.0])
                    .title("time")
                    .style(Style::default().fg(Color::Yellow)),
            );
        chart
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

    fn parse_char_data(&mut self, nets: &Vec<WifiInfo>) {
        self.signal_tick += 1.0;
        for w in nets {
            let seconds: f64 = w.time.second() as f64;
            if let Some(n) = self
                .wifi_datasets
                .iter_mut()
                .find(|item| item.ssid == w.ssid)
            {
                // println!("{}", self.signal_tick);
                let signal: f64 = w.signal as f64;
                n.data.push((signal * -1.0, seconds));
                // n.data.push((signal * -1.0, self.signal_tick));
                if n.data.len() > 50 {
                    // let d = n.data.drai
                }
                // n.data = n.data[n.data.len()-50]
                // n.data = n.data.clone().into_iter().take(50).collect();
            } else {
                self.wifi_datasets.push(WifiDataset {
                    ssid: w.ssid.clone(),
                    data: vec![(0.0, 0.0)],
                });
            }
        }
        // println!("{:?}", self.wifi_datasets);
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
            // self.wifis = nets;
            self.parse_char_data(&nets);
            self.wifis = nets;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, rect: Rect) -> Result<()> {
        let rects = Layout::default()
            .direction(Direction::Vertical)
            // .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .constraints(vec![Constraint::Length(15), Constraint::Length(50)])
            .split(f.size());

        let mut rect = rects[0];
        // rect.y = 1;

        let block = self.make_table();
        f.render_widget(block, rect);

        let block = self.make_chart();
        f.render_widget(block, rects[1]);

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

        // f.render_widget(block, rect);
        Ok(())
    }
}

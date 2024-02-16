use crate::components::wifi_scan::WifiInfo;
use chrono::Timelike;
use color_eyre::eyre::Result;
use pnet::datalink::{self, NetworkInterface};
use ratatui::{prelude::*, widgets::*};
use std::collections::HashMap;
use std::process::{Command, Output};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, tui::Frame};

#[derive(Debug)]
pub struct WifiDataset {
    ssid: String,
    data: Vec<(f64, f64)>,
    color: Color,
}

pub struct WifiChart {
    action_tx: Option<UnboundedSender<Action>>,
    last_update_time: Instant,
    wifi_datasets: Vec<WifiDataset>,
    signal_tick: [f64; 2],
    show_graph: bool,
}

impl Default for WifiChart {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiChart {
    pub fn new() -> Self {
        Self {
            show_graph: false,
            action_tx: None,
            last_update_time: Instant::now(),
            wifi_datasets: Vec::new(),
            signal_tick: [0.0, 40.0],
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }

    fn parse_char_data(&mut self, nets: &Vec<WifiInfo>) {
        for w in nets {
            let seconds: f64 = w.time.second() as f64;
            if let Some(p) = self
                .wifi_datasets
                .iter_mut()
                .position(|item| item.ssid == w.ssid)
            {
                let n = &mut self.wifi_datasets[p];
                let signal: f64 = w.signal as f64;
                n.data.push((self.signal_tick[1], signal * -1.0));
                if n.data.len() > 50 {
                    n.data.remove(0);
                }
            } else {
                self.wifi_datasets.push(WifiDataset {
                    ssid: w.ssid.clone(),
                    data: vec![(0.0, 0.0)],
                    color: w.color.clone(),
                });
            }
        }
        self.signal_tick[0] += 1.0;
        self.signal_tick[1] += 1.0;
    }

    pub fn make_chart(&mut self) -> Chart {
        let mut datasets = Vec::new();
        let mut index = 0;

        for d in &self.wifi_datasets {
            let dataset = Dataset::default()
                .name(d.ssid.clone())
                .marker(symbols::Marker::Dot)
                .style(Style::default().fg(d.color.clone()))
                .graph_type(GraphType::Line)
                .data(&d.data);
            datasets.push(dataset);
            index += 1;
        }

        let x_labels = [
            self.signal_tick[0].to_string(),
            (((self.signal_tick[1] - self.signal_tick[0]) / 2.0) + self.signal_tick[0]).to_string(),
            self.signal_tick[1].to_string(),
        ]
        .iter()
        .cloned()
        .map(Span::from)
        .collect();

        let chart = Chart::new(datasets)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from("|WiFi signals|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|hide ", Style::default().fg(Color::Yellow)),
                            Span::styled("g", Style::default().fg(Color::Red)),
                            Span::styled("raph|", Style::default().fg(Color::Yellow)),
                        ]))
                        .position(ratatui::widgets::block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .borders(Borders::ALL)
                    .padding(Padding::new(1, 1, 1, 1)),
            )
            .y_axis(
                Axis::default()
                    .bounds([25.0, 100.0])
                    .title("[signal(dbm)]")
                    .labels(
                        ["-25.0", "-52.0", "-100.0"]
                            .iter()
                            .cloned()
                            .map(Span::from)
                            .collect(),
                    )
                    .style(Style::default().fg(Color::Yellow)),
            )
            .x_axis(
                Axis::default()
                    .bounds(self.signal_tick)
                    .title("[scans]")
                    .labels(x_labels)
                    .style(Style::default().fg(Color::Yellow)),
            )
            .legend_position(Some(LegendPosition::TopLeft))
            .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)));
        chart
    }
}

impl Component for WifiChart {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }
        // -- custom actions
        if let Action::Scan(ref nets) = action {
            self.parse_char_data(nets);
        }

        if let Action::GraphToggle = action {
            self.show_graph = !self.show_graph;
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.show_graph {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(area);
            let rect = Rect::new(0, 1, area.width / 2, layout[0].height);

            let block = self.make_chart();
            f.render_widget(block, rect);
        }
        Ok(())
    }
}

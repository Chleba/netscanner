use color_eyre::eyre::Result;
use pnet::datalink::{self, NetworkInterface};
use ratatui::{prelude::*, widgets::*};
use std::collections::HashMap;
use std::process::{Command, Output};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{action::Action, mode::Mode, tui::Frame};

#[derive(Debug, PartialEq)]
struct WifiConn {
    interface: String,
    ifindex: u8,
    mac: String,
    ssid: String,
    channel: String,
    txpower: String,
}

struct CommandError {
    desc: String,
}

pub struct WifiInterface {
    action_tx: Option<UnboundedSender<Action>>,
    last_update: Instant,
    wifi_info: Option<WifiConn>,
}

impl Default for WifiInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiInterface {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            last_update: Instant::now(),
            wifi_info: None,
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let elapsed = (now - self.last_update).as_secs_f64();

        if self.wifi_info == None || elapsed > 5.0 {
            self.last_update = now;
            self.get_connected_wifi_info();
        }
        Ok(())
    }

    fn iw_command(&mut self, intf_name: String) -> Result<Output, CommandError> {
        let iw_output = Command::new("iw")
            .arg("dev")
            .arg(intf_name)
            .arg("info")
            .output()
            .map_err(|e| CommandError {
                desc: format!("command failed: {}", e),
            })?;
        if iw_output.status.success() {
            Ok(iw_output)
        } else {
            Err(CommandError {
                desc: "command failed".to_string(),
            })
        }
    }

    fn parse_iw_command(&mut self, output: String) -> WifiConn {
        let lines = output.lines();
        let mut hash = HashMap::new();
        for l in lines {
            let split = l.trim().split(" ").collect::<Vec<&str>>();
            if split.len() > 1 {
                hash.insert(split[0], split[1].trim());
            }
        }
        WifiConn {
            interface: hash
                .get("Interface")
                .unwrap_or(&"")
                .parse::<String>()
                .unwrap_or(String::from("")),
            ssid: hash.get("ssid").unwrap_or(&"").parse::<String>().unwrap_or(String::from("")),
            ifindex: hash.get("ifindex").unwrap_or(&"").parse::<u8>().unwrap_or(0),
            mac: hash.get("addr").unwrap_or(&"").parse::<String>().unwrap_or(String::from("")),
            channel: hash
                .get("channel")
                .unwrap_or(&"")
                .parse::<String>()
                .unwrap_or(String::from("")),
            txpower: hash
                .get("txpower")
                .unwrap_or(&"")
                .parse::<String>()
                .unwrap_or(String::from("")),
        }
    }

    fn get_connected_wifi_info(&mut self) {
        let interfaces = datalink::interfaces();
        for i in interfaces {
            match self.iw_command(i.name) {
                Ok(output) => {
                    let o = String::from_utf8(output.stdout).unwrap_or(String::from(""));
                    self.wifi_info = Some(self.parse_iw_command(o));
                }
                Err(_) => (),
            }
        }
    }

    fn make_list(&mut self) -> List {
        if let Some(wifi_info) = &self.wifi_info {
            let interface = &wifi_info.interface;
            let interface_label = "Interface:";
            let ssid = &wifi_info.ssid.clone();
            let ssid_label = "SSID:";
            let ifindex = &wifi_info.ifindex;
            let ifindex_label = "Intf index:";
            let channel = &wifi_info.channel.clone();
            let channel_label = "Channel:";
            let txpower = &wifi_info.txpower.clone();
            let txpower_label = "TxPower:";
            let mac = &wifi_info.mac.clone();
            let mac_label = "Mac addr:";

            // let list = List::new()
            let mut items: Vec<ListItem> = Vec::new();
            // let list = List::new(items);

            items.push(ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{ssid_label:<12}"),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(format!("{ssid:<12}"), Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("{channel_label:<12}"),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(format!("{channel:<12}"), Style::default().fg(Color::Green)),
                ]),
            ]));

            let list = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("|WiFi Interface|")
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    // .border_type(BorderType::Rounded)
                    .title_style(Style::default().fg(Color::Yellow))
                    .title_alignment(Alignment::Right),
            );

            list

            // List::new::<ListItem>(vec![ListItem::new(vec![
            //     // Line::from(vec![
            //     //     Span::styled(
            //     //         format!("{interface_label:<12}"),
            //     //         Style::default().fg(Color::White),
            //     //     ),
            //     //     Span::styled(
            //     //         format!("{interface:<12}"),
            //     //         Style::default().fg(Color::Green),
            //     //     ),
            //     // ]),

            //     Line::from(vec![
            //         Span::styled(
            //             format!("{ssid_label:<12}"),
            //             Style::default().fg(Color::White),
            //         ),
            //         Span::styled(
            //             format!("{ssid:<12}"),
            //             Style::default().fg(Color::Green),
            //         ),
            //     ]),

            //     // Line::from(vec![
            //     //     Span::styled(
            //     //         format!("{mac_label:<12}"),
            //     //         Style::default().fg(Color::White),
            //     //     ),
            //     //     Span::styled(
            //     //         format!("{mac:<12}"),
            //     //         Style::default().fg(Color::Green),
            //     //     ),
            //     // ]),

            //     // Line::from(vec![
            //     //     Span::styled(
            //     //         format!("{txpower_label:<12}"),
            //     //         Style::default().fg(Color::White),
            //     //     ),
            //     //     Span::styled(
            //     //         format!("{txpower}dBm"),
            //     //         Style::default().fg(Color::Green),
            //     //     ),
            //     // ]),

            //     Line::from(vec![
            //         Span::styled(
            //             format!("{channel_label:<12}"),
            //             Style::default().fg(Color::White),
            //         ),
            //         Span::styled(
            //             format!("{channel:<12}"),
            //             Style::default().fg(Color::Green),
            //         ),
            //     ]),
            //     ])
            // ])
            //     .block(
            //         Block::default()
            //             .borders(Borders::ALL)
            //             .title("|WiFi Interface|")
            //             .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
            //             // .border_type(BorderType::Rounded)
            //             .title_style(Style::default().fg(Color::Yellow))
            //             .title_alignment(Alignment::Right),
            //     )
        } else {
            let items: Vec<ListItem> = Vec::new();
            List::new(items)
        }
    }
}

impl Component for WifiInterface {
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
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        let rect = Rect::new(
            (area.width / 2) + 1,
            (layout[0].y + layout[0].height) - 4,
            (area.width / 2) - 2,
            4,
        );

        let block = self.make_list();
        f.render_widget(block, rect);

        Ok(())
    }
}

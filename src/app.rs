use chrono::{DateTime, Local};
use color_eyre::eyre::Result;
use crossterm::event::KeyEvent;
use ratatui::prelude::Rect;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::{
    action::Action,
    components::{
        discovery::{self, Discovery, ScannedIp},
        export::Export,
        interfaces::Interfaces,
        packetdump::PacketDump,
        ports::{Ports, ScannedIpPorts},
        tabs::Tabs,
        title::Title,
        wifi_chart::WifiChart,
        wifi_interface::WifiInterface,
        wifi_scan::WifiScan,
        Component,
    },
    config::Config,
    enums::{ExportData, PacketTypeEnum, PacketsInfoTypesEnum},
    mode::Mode,
    tui,
};

pub struct App {
    pub config: Config,
    pub tick_rate: f64,
    pub frame_rate: f64,
    pub components: Vec<Box<dyn Component>>,
    pub should_quit: bool,
    pub should_suspend: bool,
    pub mode: Mode,
    pub last_tick_key_events: Vec<KeyEvent>,
    pub action_tx: UnboundedSender<Action>,
    pub action_rx: UnboundedReceiver<Action>,
    pub post_exist_msg: Option<String>,
}

impl App {
    pub fn new(tick_rate: f64, frame_rate: f64) -> Result<Self> {
        let title = Title::new();
        let interfaces = Interfaces::default();
        let wifiscan = WifiScan::default();
        let wifi_interface = WifiInterface::default();
        let wifi_chart = WifiChart::default();
        let tabs = Tabs::default();
        let discovery = Discovery::default();
        let packetdump = PacketDump::default();
        let ports = Ports::default();
        let export = Export::default();
        let config = Config::new()?;

        let mode = Mode::Normal;
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        Ok(Self {
            tick_rate: 10.0,
            frame_rate,
            components: vec![
                Box::new(title),
                Box::new(interfaces),
                Box::new(wifiscan),
                Box::new(wifi_interface),
                Box::new(wifi_chart),
                Box::new(tabs),
                Box::new(discovery),
                Box::new(packetdump),
                Box::new(ports),
                Box::new(export),
            ],
            should_quit: false,
            should_suspend: false,
            config,
            mode,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            post_exist_msg: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // let (action: action_rx_tx, mut action_rx) = mpsc::unbounded_channel();
        let action_tx = &self.action_tx;
        let action_rx = &mut self.action_rx;

        let mut tui = tui::Tui::new()?
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate);
        // tui.mouse(true);
        tui.enter()?;

        for component in self.components.iter_mut() {
            component.register_action_handler(action_tx.clone())?;
        }

        for component in self.components.iter_mut() {
            component.register_config_handler(self.config.clone())?;
        }

        for component in self.components.iter_mut() {
            component.init(tui.size()?)?;
        }

        loop {
            if let Some(e) = tui.next().await {
                match e {
                    tui::Event::Quit => action_tx.send(Action::Quit)?,
                    tui::Event::Tick => action_tx.send(Action::Tick)?,
                    tui::Event::Render => action_tx.send(Action::Render)?,
                    tui::Event::Resize(x, y) => action_tx.send(Action::Resize(x, y))?,
                    tui::Event::Key(key) => {
                        if let Some(keymap) = self.config.keybindings.get(&self.mode) {
                            if let Some(action) = keymap.get(&vec![key]) {
                                log::info!("Got action: {action:?}");
                                action_tx.send(action.clone())?;
                            } else {
                                // If the key was not handled as a single key action,
                                // then consider it for multi-key combinations.
                                self.last_tick_key_events.push(key);

                                // Check for multi-key combinations
                                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                                    log::info!("Got action: {action:?}");
                                    action_tx.send(action.clone())?;
                                }
                            }
                        };
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.handle_events(Some(e.clone()))? {
                        action_tx.send(action)?;
                    }
                }
            }

            while let Ok(action) = action_rx.try_recv() {
                if action != Action::Tick && action != Action::Render {
                    log::debug!("{action:?}");
                }
                match action {
                    Action::AppModeChange(mode) => {
                        self.mode = mode;
                    }

                    Action::Error(ref err_msg) => {
                        self.post_exist_msg = Some(err_msg.to_string());
                        self.should_quit = true;
                    }

                    Action::Export => {
                        // get data from specific components by downcasting them and then try to
                        // comvert into specific struct
                        let mut scanned_ips: Vec<ScannedIp> = Vec::new();
                        let mut scanned_ports: Vec<ScannedIpPorts> = Vec::new();
                        let mut arp_packets: Vec<(DateTime<Local>, PacketsInfoTypesEnum)> = Vec::new();
                        let mut udp_packets = Vec::new();
                        let mut tcp_packets = Vec::new();
                        let mut icmp_packets = Vec::new();
                        let mut icmp6_packets = Vec::new();

                        for component in &self.components {
                            if let Some(d) = component.as_any().downcast_ref::<Discovery>() {
                                scanned_ips = d.get_scanned_ips().to_vec();
                            } else if let Some(pd) = component.as_any().downcast_ref::<PacketDump>() {
                                arp_packets = pd.clone_array_by_packet_type(PacketTypeEnum::Arp);
                                udp_packets = pd.clone_array_by_packet_type(PacketTypeEnum::Udp);
                                tcp_packets = pd.clone_array_by_packet_type(PacketTypeEnum::Tcp);
                                icmp_packets = pd.clone_array_by_packet_type(PacketTypeEnum::Icmp);
                                icmp6_packets = pd.clone_array_by_packet_type(PacketTypeEnum::Icmp6);
                            } else if let Some(p) = component.as_any().downcast_ref::<Ports>() {
                                scanned_ports = p.get_scanned_ports().to_vec();
                            }
                        }
                        action_tx
                            .send(Action::ExportData(ExportData {
                                scanned_ips,
                                scanned_ports,
                                arp_packets,
                                udp_packets,
                                tcp_packets,
                                icmp_packets,
                                icmp6_packets,
                            }))
                            .unwrap();
                    }

                    Action::Tick => {
                        self.last_tick_key_events.drain(..);
                    }
                    Action::Quit => self.should_quit = true,
                    Action::Suspend => self.should_suspend = true,
                    Action::Resume => self.should_suspend = false,
                    Action::Resize(w, h) => {
                        tui.resize(Rect::new(0, 0, w, h))?;
                        tui.draw(|f| {
                            for component in self.components.iter_mut() {
                                let r = component.draw(f, f.size());
                                if let Err(e) = r {
                                    action_tx
                                        .send(Action::Error(format!("Failed to draw: {:?}", e)))
                                        .unwrap();
                                }
                            }
                        })?;
                    }
                    Action::Render => {
                        tui.draw(|f| {
                            for component in self.components.iter_mut() {
                                let r = component.draw(f, f.size());
                                if let Err(e) = r {
                                    action_tx
                                        .send(Action::Error(format!("Failed to draw: {:?}", e)))
                                        .unwrap();
                                }
                            }
                        })?;
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.update(action.clone())? {
                        action_tx.send(action)?
                    };
                }
            }
            if self.should_suspend {
                tui.suspend()?;
                action_tx.send(Action::Resume)?;
                tui = tui::Tui::new()?
                    .tick_rate(self.tick_rate)
                    .frame_rate(self.frame_rate);
                // tui.mouse(true);
                tui.enter()?;
            } else if self.should_quit {
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;

        if let Some(ref s) = self.post_exist_msg {
            println!("`netscanner` failed with Error:");
            println!("{}", s);
        }

        Ok(())
    }
}

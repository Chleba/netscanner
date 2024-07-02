use color_eyre::eyre::{Ok, Result};
use csv::Writer;
use ratatui::{prelude::*, widgets::*};
use std::env;
use tokio::sync::mpsc::UnboundedSender;

use super::{discovery::ScannedIp, ports::ScannedIpPorts, Component, Frame};
use crate::action::Action;

#[derive(Default)]
pub struct Export {
    action_tx: Option<UnboundedSender<Action>>,
    home_dir: String,
}

impl Export {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            home_dir: String::new(),
        }
    }

    fn get_user_home_dir(&mut self) {
        let mut home_dir = String::from("/root");
        if let Some(h_dir) = env::var_os("HOME") {
            home_dir = String::from(h_dir.to_str().unwrap());
        }
        if let Some(sudo_user) = env::var_os("SUDO_USER") {
            home_dir = format!("/home/{}", sudo_user.to_str().unwrap());
        }
        self.home_dir = format!("{}/.netscanner", home_dir);

        // -- create dot folder
        if std::fs::metadata(self.home_dir.clone()).is_err() {
            if std::fs::create_dir_all(self.home_dir.clone()).is_err() {
                println!("Failed to create export dir");
            }
        }
    }

    pub fn write_discovery(&mut self, data: Vec<ScannedIp>) -> Result<()> {
        let mut w = Writer::from_path(format!("{}/scanned_ips.csv", self.home_dir))?;

        // -- header
        w.write_record(["ip", "mac", "hostname", "vendor"])?;
        for s_ip in data {
            w.write_record([s_ip.ip, s_ip.mac, s_ip.hostname, s_ip.vendor])?;
        }
        w.flush()?;

        Ok(())
    }

    pub fn write_ports(&mut self, data: Vec<ScannedIpPorts>) -> Result<()> {
        let mut w = Writer::from_path(format!("{}/scanned_ports.csv", self.home_dir))?;

        // -- header
        w.write_record(["ip", "ports"])?;
        for s_ip in data {
            let ports: String = s_ip.ports.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(":");
            w.write_record([s_ip.ip, ports])?;
        }
        w.flush()?;

        Ok(())
    }
}

impl Component for Export {
    fn init(&mut self, area: Rect) -> Result<()> {
        self.get_user_home_dir();
        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::Export => {}
            Action::ExportData(data) => {
                let _ = self.write_discovery(data.scanned_ips);
                let _ = self.write_ports(data.scanned_ports);
            }
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        // let rect = Rect::new(0, 0, f.size().width, 1);
        // let version: &str = env!("CARGO_PKG_VERSION");
        // let title = format!(" Network Scanner (v{})", version);
        // f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}


use color_eyre::eyre::Result;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::Sender;

use super::{Component, Frame};
use crate::{
    action::Action,
    config::Config,
};

#[derive(Default)]
pub struct Title {
    command_tx: Option<Sender<Action>>,
    config: Config,
}

impl Title {
    pub fn new() -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
        }
    }
}

impl Component for Title {
    fn register_action_handler(&mut self, action_tx: Sender<Action>) -> Result<()> {
        self.command_tx = Some(action_tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let rect = Rect::new(0, 0, f.area().width, 1);
        let version: &str = env!("CARGO_PKG_VERSION");
        let title = format!(" Network Scanner (v{})", version);
        f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}

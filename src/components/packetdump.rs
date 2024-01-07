use std::{collections::HashMap, time::Duration};

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{prelude::*, widgets::*};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
};

pub struct PacketDump {
    action_tx: Option<UnboundedSender<Action>>,
    loop_task: JoinHandle<()>,
    should_quit: bool,
}

impl PacketDump {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            loop_task: tokio::spawn(async {}),
            should_quit: false,
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Default for PacketDump {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for PacketDump {
    fn init(&mut self, area: Rect) -> Result<()> {
        // let tx = self.action_tx.clone().unwrap();
        // let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

        self.loop_task = tokio::spawn(async move {
            let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
            loop {
                let mut should_quit = false;
                while let Ok(action) = action_rx.try_recv() {
                    if action == Action::Quit {
                        should_quit = true;
                    }
                }
                if should_quit {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
        Ok(())
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }

        if let Action::Quit = action {
            println!("MASLO ABORT");
            self.should_quit = true;
            // self.loop_task.abort();
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let rect = Rect::new(20, 0, f.size().width - 20, 1);
        let title = format!(" hovno");
        f.render_widget(Paragraph::new(title), rect);
        Ok(())
    }
}

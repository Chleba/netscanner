use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use ratatui::{prelude::*, widgets::*};
use ratatui::{
    text::{Line, Span},
    widgets::{block::Title, Paragraph},
};
// use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{KeyCode, KeyEvent};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
    enums::TabsEnum,
    layout::get_vertical_layout,
};

#[derive(Default)]
pub struct Tabs {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    tab_index: usize,
}

impl Tabs {
    pub fn new() -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
            tab_index: 0,
        }
    }

    fn make_tabs(&self) -> Paragraph {
        let enum_titles = TabsEnum::iter()
            .enumerate()
            .map(|(idx, p)| {
                if idx == self.tab_index {
                    let arrrow = String::from(char::from_u32(0x25bc).unwrap_or('>'));
                    Span::styled(format!("{}{} ", p, arrrow), Style::default().fg(Color::Green).bold())
                } else {
                    Span::styled(format!("{} ", p), Style::default().fg(Color::DarkGray))
                }
            })
            .collect::<Vec<Span>>();

        let title = Title::from(Line::from(vec![
            "|".yellow(),
            "<T>".red().bold(),
            "abs|".yellow(),
        ]))
        .alignment(Alignment::Right);
        let b = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(100, 100, 100)));

        Paragraph::new(Line::from(enum_titles)).block(b)
    }
}

impl Component for Tabs {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::Tick => {}

            Action::Tab => {
                let new_tab_index = self.tab_index + 1;
                self.tab_index = new_tab_index % (TabsEnum::COUNT);
            }

            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = get_vertical_layout(area);
        let mut rect = layout.tabs;
        rect.y += 1;

        let tabs = self.make_tabs();
        f.render_widget(tabs, rect);

        // let title = Title::from(Line::from(vec!["|".yellow(), "<T>".red(), "abs|".yellow()]))
        //     .alignment(Alignment::Right);
        // let b = Block::default()
        //     .title(title)
        //     .borders(Borders::ALL)
        //     .border_style(Style::default().fg(Color::Rgb(100, 100, 100)));

        // f.render_widget(b, rect);

        Ok(())
    }
}

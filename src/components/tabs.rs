use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{prelude::*, widgets::*};
use ratatui::{
    text::{Line, Span},
    widgets::{block::Title, Paragraph},
};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use super::{Component, Frame};
use crate::{
    action::Action,
    config::{Config, KeyBindings},
    enums::TabsEnum,
    layout::get_vertical_layout,
    config::DEFAULT_BORDER_STYLE,
};

#[derive(Default)]
pub struct Tabs {
    action_tx: Option<UnboundedSender<Action>>,
    config: Config,
    tab_index: usize,
}

impl Tabs {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            config: Config::default(),
            tab_index: 0,
        }
    }

    fn make_tabs(&self) -> Paragraph {
        let enum_titles = TabsEnum::iter()
            .enumerate()
            .map(|(idx, p)| {
                if idx == self.tab_index {
                    // let index_str = idx + 1;
                    Span::styled(
                        // format!("({}){} ", index_str, p),
                        format!("{} ", p),
                        Style::default().fg(Color::Green).bold(),
                    )
                } else {
                    Span::styled(format!("{} ", p), Style::default().fg(Color::DarkGray))
                }
            })
            .collect::<Vec<Span>>();

        let title = Title::from(Line::from(vec![
            "|".yellow(),
            "<Tab>".red().bold(),
            "s|".yellow(),
        ]))
        .alignment(Alignment::Right);

        let arrrow = String::from(char::from_u32(0x25bc).unwrap_or('>'));
        let b = Block::default()
            .title(title)
            .title(
                Title::from(Line::from(vec!["|".yellow(), arrrow.green(), "|".yellow()]))
                    .alignment(Alignment::Center)
                    .position(block::Position::Bottom),
            )
            .borders(Borders::ALL)
            .border_type(DEFAULT_BORDER_STYLE)
            .padding(Padding::new(1, 0, 0, 0))
            .border_style(Style::default().fg(Color::Rgb(100, 100, 100)));

        Paragraph::new(Line::from(enum_titles)).block(b)
    }

    fn next_tab(&mut self) {
        let new_tab_index = self.tab_index + 1;
        self.tab_index = new_tab_index % (TabsEnum::COUNT);

        let tab_enum: TabsEnum = TabsEnum::iter().nth(self.tab_index).unwrap();
        self.action_tx
            .clone()
            .unwrap()
            .send(Action::TabChange(tab_enum))
            .unwrap();
    }
}

impl Component for Tabs {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
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
                self.next_tab();
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

        Ok(())
    }
}

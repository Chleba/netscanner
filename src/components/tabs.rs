use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};
use ratatui::{
    text::{Line, Span},
    widgets::{block::Title, Paragraph},
};
use strum::{EnumCount, IntoEnumIterator};
use tokio::sync::mpsc::Sender;

use super::{Component, Frame};
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    config::Config,
    enums::TabsEnum,
    layout::get_vertical_layout,
};

#[derive(Default)]
pub struct Tabs {
    action_tx: Option<Sender<Action>>,
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

    fn make_tabs(&self) -> Paragraph<'_> {
        let enum_titles: Vec<Span> =
            TabsEnum::iter()
                .enumerate()
                .fold(Vec::new(), |mut title_spans, (idx, p)| {
                    let index_str = idx + 1;

                    let s1 = "(".yellow();
                    let s2 = format!("{}", index_str).red();
                    let s3 = ")".yellow();
                    let mut s4 = format!("{} ", p).dark_gray().bold();
                    if idx == self.tab_index {
                        s4 = format!("{} ", p).green().bold();
                    }

                    title_spans.push(s1);
                    title_spans.push(s2);
                    title_spans.push(s3);
                    title_spans.push(s4);
                    title_spans
                });

        let title = Title::from(Line::from(vec![
            "|".yellow(),
            "Tab".red().bold(),
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
        self.tab_index = (self.tab_index + 1) % TabsEnum::COUNT;
        if let Some(ref action_tx) = self.action_tx {
            let tab_enum = TabsEnum::iter().nth(self.tab_index).unwrap();
            action_tx.try_send(Action::TabChange(tab_enum)).unwrap();
        }
    }
}

impl Component for Tabs {
    fn register_action_handler(&mut self, tx: Sender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::Tab => {
                self.next_tab();
            }

            Action::TabChange(tab_enum) => TabsEnum::iter().enumerate().for_each(|(idx, t)| {
                if tab_enum == t {
                    self.tab_index = idx;
                }
            }),

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

use crate::components::sniff::IPTraffic;
use crate::utils::{bytes_convert, count_traffic_total};
use color_eyre::owo_colors::OwoColorize;
use ratatui::style::Stylize;
use ratatui::{layout::Size, prelude::*, widgets::*};
use tui_scrollview::{ScrollView, ScrollViewState};

#[derive(Debug)]
pub struct TrafficScroll {
    pub traffic_ips: Vec<IPTraffic>,
}

impl StatefulWidget for TrafficScroll {
    type State = ScrollViewState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let c_size = Size::new(area.width-1, (3 * self.traffic_ips.len()) as u16);
        let mut scrollview = ScrollView::new(c_size);
        let total = count_traffic_total(&self.traffic_ips);

        for (index, item) in self.traffic_ips.iter().enumerate() {
            // -- title
            let b_rect = Rect {
                x: 1,
                y: (index * 3) as u16,
                width: area.width - 3,
                height: 3,
            };
            let b = Block::default()
                .borders(Borders::NONE)
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .title_style(Style::default().fg(Color::Blue))
                .title(Line::from(vec![
                    format!("{}", item.ip).blue(),
                    format!(" ({})", item.hostname.clone()).magenta(),
                ]));
            scrollview.render_widget(b, b_rect);

            // -- download gauge
            let gd = LineGauge::default()
                .label(Line::from(vec![
                    "D:".yellow(),
                    bytes_convert(item.download).green(),
                ]))
                .ratio(item.download / total.0)
                .filled_style(Style::default().fg(Color::Green))
                // .unfilled_style(Style::default().fg(Color::Rgb(100, 100, 100)));
                .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 60)));
            let gd_rect = Rect {
                x: 1,
                y: ((index * 3) + 1) as u16,
                width: ((area.width - 2) / 2) - 2,
                height: 1,
            };
            scrollview.render_widget(gd, gd_rect);

            // -- upload gauge
            let gu = LineGauge::default()
                .label(Line::from(vec![
                    "U:".yellow(),
                    bytes_convert(item.upload).red(),
                ]))
                .ratio(item.upload / total.1)
                .filled_style(Style::default().fg(Color::Red))
                .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 60)));
            let gu_rect = Rect {
                x: (area.width - 2) / 2,
                y: ((index * 3) + 1) as u16,
                width: (area.width - 2) / 2,
                height: 1,
            };
            scrollview.render_widget(gu, gu_rect);
        }

        scrollview.render(area, buf, state);
    }
}

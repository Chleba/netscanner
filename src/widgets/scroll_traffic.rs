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

impl TrafficScroll {
    fn safe_ratio(value: f64, total: f64) -> f64 {
        if total <= 0.0 {
            return 0.0;
        }
        (value / total).clamp(0.0, 1.0)
    }
}

impl StatefulWidget for TrafficScroll {
    type State = ScrollViewState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let c_size = Size::new(area.width - 2, (3 * self.traffic_ips.len()) as u16);
        let mut scrollview = ScrollView::new(c_size);
        let total = count_traffic_total(&self.traffic_ips);

        for (index, item) in self.traffic_ips.iter().enumerate() {
            // -- title row
            let b_rect = Rect {
                x: 0,
                y: (index * 3) as u16,
                width: c_size.width,
                height: 1,
            };
            let b = Block::default()
                .borders(Borders::NONE)
                .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                .title_style(Style::default().fg(Color::Blue))
                .title(Line::from(vec![
                    Span::styled(item.ip.to_string(), Style::default().fg(Color::Blue)),
                    Span::styled(format!(" ({})", item.hostname.clone()), Style::default().fg(Color::Magenta)),
                ]));
            scrollview.render_widget(b, b_rect);

            // -- data row: D label + D bar | U label + U bar
            let row_y = ((index * 3) + 1) as u16;
            let row_width = c_size.width.saturating_sub(2);

            // Split into two halves: left for download, right for upload
            let half_width = (row_width / 2).saturating_sub(1);

            // -- Download line gauge (left half)
            let d_ratio = Self::safe_ratio(item.download, total.0);
            let d_label = format!("D: {}", bytes_convert(item.download));
            let d_gauge = LineGauge::default()
                .ratio(d_ratio)
                .label(Span::styled(&d_label, Style::default().fg(Color::Green)))
                .filled_style(Style::default().fg(Color::Green))
                .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 60)));
            scrollview.render_widget(d_gauge, Rect {
                x: 1,
                y: row_y,
                width: half_width,
                height: 1,
            });

            // -- Upload line gauge (right half)
            let u_ratio = Self::safe_ratio(item.upload, total.1);
            let u_label = format!("U: {}", bytes_convert(item.upload));
            let u_gauge = LineGauge::default()
                .ratio(u_ratio)
                .label(Span::styled(&u_label, Style::default().fg(Color::Red)))
                .filled_style(Style::default().fg(Color::Red))
                .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 60)));
            scrollview.render_widget(u_gauge, Rect {
                x: 1 + half_width as u16,
                y: row_y,
                width: half_width,
                height: 1,
            });

            // -- spacer row
            let spacer_rect = Rect {
                x: 0,
                y: ((index * 3) + 2) as u16,
                width: c_size.width,
                height: 1,
            };
            scrollview.render_widget(Paragraph::new(""), spacer_rect);
        }

        scrollview.render(area, buf, state);
    }
}

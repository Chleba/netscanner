use ratatui::prelude::*;

const VERTICAL_TOP_PERCENT: u16 = 40;
const VERTICAL_BOTTOM_PERCENT: u16 = 60;

const HORIZONTAL_SPLIT: u16 = 50;

const VERTICAL_CONSTRAINTS: [Constraint; 3] = [
    Constraint::Percentage(VERTICAL_TOP_PERCENT),
    Constraint::Length(3),
    Constraint::Percentage(VERTICAL_BOTTOM_PERCENT),
];

pub const HORIZONTAL_CONSTRAINTS: [Constraint; 2] = [
    Constraint::Percentage(HORIZONTAL_SPLIT),
    Constraint::Percentage(HORIZONTAL_SPLIT),
];

pub struct VerticalLayoutRects {
    pub top: Rect,
    pub tabs: Rect,
    pub bottom: Rect,
}

pub struct HorizontalLayoutRects {
    pub left: Rect,
    pub right: Rect,
}

pub fn get_vertical_layout(area: Rect) -> VerticalLayoutRects {
    let layout = Layout::vertical(VERTICAL_CONSTRAINTS).split(area);
    VerticalLayoutRects {
        top: layout[0],
        tabs: layout[1],
        bottom: layout[2],
    }
}

pub fn get_horizontal_layout(area: Rect) -> HorizontalLayoutRects {
    let layout = Layout::horizontal(HORIZONTAL_CONSTRAINTS).split(area);
    HorizontalLayoutRects {
        left: layout[0],
        right: layout[1],
    }
}

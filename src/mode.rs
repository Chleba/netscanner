use serde::{Deserialize, Serialize};
use ratatui::style::Color; 

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Home,
    Networks,
    Interfaces,
}

pub const MODE_ACTIVE_COLOR: Color = Color::Green;
pub const MODE_NORMAL_COLOR: Color = Color::Gray;

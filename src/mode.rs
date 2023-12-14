use serde::{Deserialize, Serialize};
use ratatui::style::Color; 

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Normal,
    Input,
}


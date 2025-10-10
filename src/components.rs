use color_eyre::eyre::Result;
use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::layout::{Rect, Size};
use std::any::Any;
use tokio::sync::mpsc::Sender;

use crate::{
    action::Action,
    config::Config,
    enums::TabsEnum,
    tui::{Event, Frame},
};

pub mod discovery;
pub mod export;
pub mod interfaces;
pub mod packetdump;
pub mod ports;
pub mod sniff;
pub mod tabs;
pub mod title;
pub mod wifi_chart;
pub mod wifi_interface;
pub mod wifi_scan;

/// `Component` is a trait that represents a visual and interactive element of the user interface.
/// Implementors of this trait can be registered with the main application loop and will be able to receive events,
/// update state, and be rendered on the screen.
pub trait Component: Any {
    /// Register an action handler that can send actions for processing if necessary.
    /// # Arguments
    /// * `tx` - A bounded sender that can send actions.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    #[allow(unused_variables)]
    fn register_action_handler(&mut self, tx: Sender<Action>) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn as_any(&self) -> &dyn Any;

    #[allow(unused_variables)]
    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        Ok(())
    }

    /// Register a configuration handler that provides configuration settings if necessary.
    /// # Arguments
    /// * `config` - Configuration settings.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    #[allow(unused_variables)]
    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        Ok(())
    }

    /// Initialize the component with a specified area if necessary.
    /// # Arguments
    /// * `area` - Rectangular area to initialize the component within.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    fn init(&mut self, _area: Size) -> Result<()> {
        Ok(())
    }

    /// Handle incoming events and produce actions if necessary.
    /// # Arguments
    /// * `event` - An optional event to be processed.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    fn handle_events(&mut self, event: Option<Event>) -> Result<Option<Action>> {
        let r = match event {
            Some(Event::Key(key_event)) => self.handle_key_events(key_event)?,
            Some(Event::Mouse(mouse_event)) => self.handle_mouse_events(mouse_event)?,
            _ => None,
        };
        Ok(r)
    }

    /// Handle key events and produce actions if necessary.
    /// # Arguments
    /// * `key` - A key event to be processed.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    #[allow(unused_variables)]
    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        Ok(None)
    }

    /// Handle mouse events and produce actions if necessary.
    /// # Arguments
    /// * `mouse` - A mouse event to be processed.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    #[allow(unused_variables)]
    fn handle_mouse_events(&mut self, mouse: MouseEvent) -> Result<Option<Action>> {
        Ok(None)
    }

    /// Update the state of the component based on a received action. (REQUIRED)
    /// # Arguments
    /// * `action` - An action that may modify the state of the component.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    #[allow(unused_variables)]
    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        Ok(None)
    }

    /// Render the component on the screen. (REQUIRED)
    /// # Arguments
    /// * `f` - A frame used for rendering.
    /// * `area` - The area in which the component should be drawn.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()>;

    /// Gracefully shutdown the component and clean up resources.
    /// This is called before the application exits to ensure proper cleanup.
    /// Components should stop any running threads, close network connections, etc.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

//! Component system for modular UI elements.
//!
//! This module defines the [`Component`] trait and exports all component implementations.
//! Components are self-contained UI elements that handle events, update state, and render
//! themselves independently.
//!
//! # Architecture
//!
//! The component system enables a **modular, loosely-coupled architecture**:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Component Trait                       │
//! │  ┌───────────────────────────────────────────────────┐  │
//! │  │  Lifecycle Methods                                │  │
//! │  │  • init()       - Initialize with terminal size   │  │
//! │  │  • shutdown()   - Cleanup resources               │  │
//! │  └───────────────────────────────────────────────────┘  │
//! │  ┌───────────────────────────────────────────────────┐  │
//! │  │  Event Handling                                   │  │
//! │  │  • handle_events()      - Process terminal events │  │
//! │  │  • handle_key_events()  - Handle keyboard         │  │
//! │  │  • handle_mouse_events() - Handle mouse           │  │
//! │  └───────────────────────────────────────────────────┘  │
//! │  ┌───────────────────────────────────────────────────┐  │
//! │  │  State Management                                 │  │
//! │  │  • update() - Process actions, update state       │  │
//! │  └───────────────────────────────────────────────────┘  │
//! │  ┌───────────────────────────────────────────────────┐  │
//! │  │  Rendering                                        │  │
//! │  │  • draw() - Render to terminal frame              │  │
//! │  └───────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Component Lifecycle
//!
//! 1. **Creation**: Component is instantiated via `Default` or `new()`
//! 2. **Registration**: Action and config handlers are registered
//! 3. **Initialization**: `init()` called with terminal size
//! 4. **Event Loop**: Component processes events and actions
//! 5. **Shutdown**: `shutdown()` called for cleanup
//!
//! # Available Components
//!
//! - **[`discovery`]**: Network host discovery via ICMP/ARP
//! - **[`ports`]**: Concurrent TCP port scanning
//! - **[`packetdump`]**: Real-time packet capture and analysis
//! - **[`sniff`]**: Network traffic monitoring
//! - **[`wifi_scan`]**: WiFi network scanning
//! - **[`wifi_chart`]**: WiFi signal strength visualization
//! - **[`wifi_interface`]**: WiFi connection information
//! - **[`interfaces`]**: Network interface selection
//! - **[`export`]**: Data export functionality
//! - **[`tabs`]**: Tab navigation UI
//! - **[`title`]**: Application title bar
//!
//! # Component Communication
//!
//! Components communicate exclusively through [`Action`] messages:
//! - Never call other components directly
//! - Send actions via the registered `action_tx` channel
//! - Receive actions via `update()` method
//! - Return new actions to be processed
//!
//! # Type Downcasting
//!
//! The `as_any()` method allows safe downcasting from `Box<dyn Component>` to
//! concrete types when needed (e.g., for data export). This is used sparingly
//! to maintain loose coupling.

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
    /// * `action_tx` - A bounded sender that can send actions.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    fn register_action_handler(&mut self, _action_tx: Sender<Action>) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn Any;

    fn tab_changed(&mut self, _tab: TabsEnum) -> Result<()> {
        Ok(())
    }

    /// Register a configuration handler that provides configuration settings if necessary.
    /// # Arguments
    /// * `config` - Configuration settings.
    /// # Returns
    /// * `Result<()>` - An Ok result or an error.
    fn register_config_handler(&mut self, _config: Config) -> Result<()> {
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
    fn handle_key_events(&mut self, _key: KeyEvent) -> Result<Option<Action>> {
        Ok(None)
    }

    /// Handle mouse events and produce actions if necessary.
    /// # Arguments
    /// * `mouse` - A mouse event to be processed.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    fn handle_mouse_events(&mut self, _mouse: MouseEvent) -> Result<Option<Action>> {
        Ok(None)
    }

    /// Update the state of the component based on a received action. (REQUIRED)
    /// # Arguments
    /// * `action` - An action that may modify the state of the component.
    /// # Returns
    /// * `Result<Option<Action>>` - An action to be processed or none.
    fn update(&mut self, _action: Action) -> Result<Option<Action>> {
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

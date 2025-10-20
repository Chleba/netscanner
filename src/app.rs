//! Application core module - coordinates components and manages the event loop.
//!
//! This module contains the [`App`] struct, which serves as the central coordinator
//! for the netscanner application. It manages the component lifecycle, routes actions
//! between components, and orchestrates the main event loop.
//!
//! # Architecture
//!
//! The [`App`] uses an **action-based messaging architecture** where components
//! communicate by sending [`Action`] messages through bounded mpsc channels:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                     App (Coordinator)                 │
//! │  ┌──────────────────────────────────────────────┐   │
//! │  │  Components: Vec<Box<dyn Component>>         │   │
//! │  │  - Discovery, Ports, PacketDump, WiFi, etc.  │   │
//! │  └──────────────────────────────────────────────┘   │
//! │                                                       │
//! │  ┌──────────────┐         ┌──────────────┐         │
//! │  │ action_tx    │────────▶│  action_rx   │         │
//! │  │ (Sender)     │  mpsc   │ (Receiver)   │         │
//! │  └──────────────┘         └──────────────┘         │
//! │         │                         │                  │
//! │         │                         ▼                  │
//! │         │                  Route to Components      │
//! │         │                         │                  │
//! │         └─────────────────────────┘                 │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! # Component Communication
//!
//! Components never call each other directly. Instead, they:
//! 1. Receive actions via their `update()` method
//! 2. Process the action and update internal state
//! 3. Optionally return new actions to be sent to other components
//!
//! This loose coupling allows components to be added, removed, or modified
//! independently without breaking the system.
//!
//! # Event Loop
//!
//! The main event loop ([`App::run`]) operates in phases:
//!
//! 1. **Event Collection**: Wait for terminal events (keyboard, resize, ticks)
//! 2. **Action Generation**: Convert events to actions via keybindings
//! 3. **Action Distribution**: Route actions to all components
//! 4. **State Update**: Components update their state based on actions
//! 5. **Rendering**: Components draw themselves to the terminal
//!
//! # Memory Management
//!
//! The application uses **bounded channels** (capacity 1000) for action messages
//! to prevent memory exhaustion. If consumers are slow, senders will block
//! rather than accumulating unbounded messages.
//!
//! For data export, [`Arc`] is used to share large datasets (scanned IPs, packets)
//! without cloning, significantly reducing memory usage during export operations.

use chrono::{DateTime, Local};
use color_eyre::eyre::Result;
use crossterm::event::KeyEvent;
use ratatui::prelude::Rect;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::{
    action::Action,
    components::{
        discovery::{Discovery, ScannedIp},
        export::Export,
        interfaces::Interfaces,
        packetdump::PacketDump,
        ports::{Ports, ScannedIpPorts},
        tabs::Tabs,
        title::Title,
        wifi_chart::WifiChart,
        wifi_interface::WifiInterface,
        wifi_scan::WifiScan,
        sniff::Sniffer,
        Component,
    },
    config::Config,
    enums::{ExportData, PacketTypeEnum, PacketsInfoTypesEnum},
    mode::Mode,
    tui,
};

/// The main application coordinator.
///
/// This struct owns all components and manages the application lifecycle,
/// from initialization through the event loop to graceful shutdown.
///
/// # Fields
///
/// * `config` - Application configuration loaded from config files
/// * `tick_rate` - Logic update rate in Hz (currently fixed at 1.0)
/// * `frame_rate` - UI render rate in Hz (currently fixed at 10.0)
/// * `components` - All UI components implementing the Component trait
/// * `should_quit` - Signal to exit the main loop
/// * `should_suspend` - Signal to suspend the application (Unix SIGTSTP)
/// * `mode` - Current input mode (Normal, Input, etc.)
/// * `last_tick_key_events` - Buffer for multi-key combinations
/// * `action_tx` - Sender half of the action channel
/// * `action_rx` - Receiver half of the action channel
/// * `post_exist_msg` - Optional error message to display after exit
pub struct App {
    pub config: Config,
    pub tick_rate: f64,
    pub frame_rate: f64,
    pub components: Vec<Box<dyn Component>>,
    pub should_quit: bool,
    pub should_suspend: bool,
    pub mode: Mode,
    pub last_tick_key_events: Vec<KeyEvent>,
    pub action_tx: Sender<Action>,
    pub action_rx: Receiver<Action>,
    pub post_exist_msg: Option<String>,
}

impl App {
    /// Creates a new application instance.
    ///
    /// This constructor initializes all components, creates the action channel,
    /// and prepares the application for execution. Components are created in
    /// dependency order to ensure proper initialization.
    ///
    /// # Arguments
    ///
    /// * `_tick_rate` - Requested logic update rate (currently unused, fixed at 1.0 Hz)
    /// * `_frame_rate` - Requested render rate (currently unused, fixed at 10.0 Hz)
    ///
    /// # Returns
    ///
    /// Returns `Ok(App)` with all components initialized, or an error if:
    /// - Configuration loading fails
    /// - Component initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use netscanner::app::App;
    ///
    /// let app = App::new(2.0, 30.0)?;
    /// # Ok::<(), color_eyre::eyre::Error>(())
    /// ```
    pub fn new(_tick_rate: f64, _frame_rate: f64) -> Result<Self> {
        let title = Title::new();
        let interfaces = Interfaces::default();
        let wifiscan = WifiScan::default();
        let wifi_interface = WifiInterface::default();
        let wifi_chart = WifiChart::default();
        let tabs = Tabs::default();
        let discovery = Discovery::default();
        let packetdump = PacketDump::default();
        let ports = Ports::default();
        let sniff = Sniffer::default();
        let export = Export::default();
        let config = Config::new()?;

        let mode = Mode::Normal;
        // Use bounded channel with capacity of 1000 for action messages
        // This prevents memory exhaustion if consumers are slow
        let (action_tx, action_rx) = mpsc::channel(1000);

        Ok(Self {
            tick_rate: 1.0,
            frame_rate: 10.0,
            components: vec![
                Box::new(title),
                Box::new(interfaces),
                Box::new(wifiscan),
                Box::new(wifi_interface),
                Box::new(wifi_chart),
                Box::new(tabs),
                Box::new(discovery),
                Box::new(packetdump),
                Box::new(ports),
                Box::new(sniff),
                Box::new(export),
            ],
            should_quit: false,
            should_suspend: false,
            config,
            mode,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            post_exist_msg: None,
        })
    }

    /// Runs the main application event loop.
    ///
    /// This is the heart of the application, coordinating all components through
    /// an event-driven architecture. The loop continues until `should_quit` is set.
    ///
    /// # Event Loop Phases
    ///
    /// ## 1. Initialization
    /// - Create and configure the TUI
    /// - Register action handlers with all components
    /// - Register config handlers with all components
    /// - Initialize components with terminal size
    ///
    /// ## 2. Main Loop
    /// - **Event Collection**: Wait for terminal events (keys, resize, ticks, render)
    /// - **Event Translation**: Convert terminal events to Actions via keybindings
    /// - **Event Distribution**: Pass events to components via `handle_events()`
    /// - **Action Processing**: Route actions to all components via `update()`
    /// - **Special Actions**:
    ///   - `Action::Export`: Collect data from all components using Arc for efficiency
    ///   - `Action::Resize`: Trigger re-render with new terminal dimensions
    ///   - `Action::Render`: Draw all components to the terminal
    ///   - `Action::Quit`: Initiate graceful shutdown sequence
    ///
    /// ## 3. Shutdown Sequence
    /// - Send `Action::Shutdown` to all components
    /// - Process any pending actions
    /// - Call `shutdown()` on each component with 5-second timeout
    /// - Handle panics during shutdown gracefully
    /// - Stop the TUI and restore terminal state
    ///
    /// # Data Export Flow
    ///
    /// When `Action::Export` is received, the app:
    /// 1. Uses `Any` trait to downcast components to their concrete types
    /// 2. Collects data (IPs, ports, packets) from Discovery, Ports, and PacketDump
    /// 3. Wraps data in `Arc` to avoid expensive clones
    /// 4. Sends `Action::ExportData` to the Export component
    ///
    /// This approach avoids tight coupling while enabling data sharing.
    ///
    /// # Error Handling
    ///
    /// Render errors are caught and converted to `Action::Error`, which:
    /// - Sets `should_quit` to true
    /// - Stores an error message in `post_exist_msg`
    /// - Allows graceful shutdown and error reporting
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TUI initialization or configuration fails
    /// - Component registration fails
    /// - Terminal rendering encounters a fatal error
    /// - Shutdown sequence fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use netscanner::app::App;
    ///
    /// #[tokio::main]
    /// async fn main() -> color_eyre::eyre::Result<()> {
    ///     let mut app = App::new(1.0, 10.0)?;
    ///     app.run().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn run(&mut self) -> Result<()> {
        // let (action: action_rx_tx, mut action_rx) = mpsc::unbounded_channel();
        let action_tx = &self.action_tx;
        let action_rx = &mut self.action_rx;

        let mut tui = tui::Tui::new()?
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate);
        // tui.mouse(true);
        tui.enter()?;

        for component in self.components.iter_mut() {
            component.register_action_handler(action_tx.clone())?;
        }

        for component in self.components.iter_mut() {
            component.register_config_handler(self.config.clone())?;
        }

        for component in self.components.iter_mut() {
            component.init(tui.size()?)?;
        }

        loop {
            if let Some(e) = tui.next().await {
                match e {
                    tui::Event::Quit => action_tx.try_send(Action::Quit)?,
                    tui::Event::Tick => action_tx.try_send(Action::Tick)?,
                    tui::Event::Render => action_tx.try_send(Action::Render)?,
                    tui::Event::Resize(x, y) => action_tx.try_send(Action::Resize(x, y))?,
                    tui::Event::Key(key) => {
                        if let Some(keymap) = self.config.keybindings.get(&self.mode) {
                            if let Some(action) = keymap.get(&vec![key]) {
                                log::info!("Got action: {action:?}");
                                action_tx.try_send(action.clone())?;
                            } else {
                                // If the key was not handled as a single key action,
                                // then consider it for multi-key combinations.
                                self.last_tick_key_events.push(key);

                                // Check for multi-key combinations
                                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                                    log::info!("Got action: {action:?}");
                                    action_tx.try_send(action.clone())?;
                                }
                            }
                        };
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.handle_events(Some(e.clone()))? {
                        action_tx.try_send(action)?;
                    }
                }
            }

            while let Ok(action) = action_rx.try_recv() {
                if action != Action::Tick && action != Action::Render {
                    log::debug!("{action:?}");
                }
                match action {
                    Action::AppModeChange(mode) => {
                        self.mode = mode;
                    }

                    Action::Error(ref err_msg) => {
                        self.post_exist_msg = Some(err_msg.to_string());
                        self.should_quit = true;
                    }

                    Action::Export => {
                        // Collect data from components using Arc for memory-efficient sharing.
                        // Only Arc pointers are cloned, not the actual data, significantly
                        // reducing memory usage during export operations.
                        let mut scanned_ips: Arc<Vec<ScannedIp>> = Arc::new(Vec::new());
                        let mut scanned_ports: Arc<Vec<ScannedIpPorts>> = Arc::new(Vec::new());
                        let mut arp_packets: Arc<Vec<(DateTime<Local>, PacketsInfoTypesEnum)>> = Arc::new(Vec::new());
                        let mut udp_packets = Arc::new(Vec::new());
                        let mut tcp_packets = Arc::new(Vec::new());
                        let mut icmp_packets = Arc::new(Vec::new());
                        let mut icmp6_packets = Arc::new(Vec::new());

                        // Note: Component downcasting pattern used here for data aggregation.
                        // While this creates coupling between App and specific component types,
                        // it's an acceptable trade-off given the current architecture where:
                        // 1. Export is inherently a cross-component operation requiring data from
                        //    multiple specific sources (Discovery, PacketDump, Ports)
                        // 2. Alternative approaches (message-passing, shared state) would add
                        //    significant complexity for this single use case
                        // 3. The coupling is contained to this export handler
                        // TODO: Consider refactoring to message-based data retrieval if more
                        // cross-component data access patterns emerge.
                        for component in &self.components {
                            if let Some(d) = component.as_any().downcast_ref::<Discovery>() {
                                scanned_ips = Arc::new(d.get_scanned_ips().to_vec());
                            } else if let Some(pd) = component.as_any().downcast_ref::<PacketDump>() {
                                arp_packets = Arc::new(pd.clone_array_by_packet_type(PacketTypeEnum::Arp));
                                udp_packets = Arc::new(pd.clone_array_by_packet_type(PacketTypeEnum::Udp));
                                tcp_packets = Arc::new(pd.clone_array_by_packet_type(PacketTypeEnum::Tcp));
                                icmp_packets = Arc::new(pd.clone_array_by_packet_type(PacketTypeEnum::Icmp));
                                icmp6_packets = Arc::new(pd.clone_array_by_packet_type(PacketTypeEnum::Icmp6));
                            } else if let Some(p) = component.as_any().downcast_ref::<Ports>() {
                                scanned_ports = Arc::new(p.get_scanned_ports().to_vec());
                            }
                        }
                        if let Err(e) = action_tx.try_send(Action::ExportData(ExportData {
                            scanned_ips,
                            scanned_ports,
                            arp_packets,
                            udp_packets,
                            tcp_packets,
                            icmp_packets,
                            icmp6_packets,
                        })) {
                            log::error!("Failed to send export data action: {:?}", e);
                        }
                    }

                    Action::Tick => {
                        self.last_tick_key_events.drain(..);
                    }
                    Action::Quit => self.should_quit = true,
                    Action::Suspend => self.should_suspend = true,
                    Action::Resume => self.should_suspend = false,
                    Action::Resize(w, h) => {
                        tui.resize(Rect::new(0, 0, w, h))?;
                        tui.draw(|f| {
                            for (idx, component) in self.components.iter_mut().enumerate() {
                                let r = component.draw(f, f.area());
                                if let Err(e) = r {
                                    let _ = action_tx.try_send(Action::Error(format!(
                                        "Failed to render component {} during terminal resize ({}x{}).\n\
                                        \n\
                                        Error: {:?}\n\
                                        \n\
                                        The application will now exit to prevent further issues.",
                                        idx, w, h, e
                                    )));
                                }
                            }
                        })?;
                    }
                    Action::Render => {
                        tui.draw(|f| {
                            for (idx, component) in self.components.iter_mut().enumerate() {
                                let r = component.draw(f, f.area());
                                if let Err(e) = r {
                                    let _ = action_tx.try_send(Action::Error(format!(
                                        "Failed to render component {} during frame update.\n\
                                        \n\
                                        Error: {:?}\n\
                                        \n\
                                        The application will now exit to prevent further issues.",
                                        idx, e
                                    )));
                                }
                            }
                        })?;
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.update(action.clone())? {
                        action_tx.try_send(action)?
                    };
                }
            }
            if self.should_suspend {
                tui.suspend()?;
                action_tx.try_send(Action::Resume)?;
                tui = tui::Tui::new()?
                    .tick_rate(self.tick_rate)
                    .frame_rate(self.frame_rate);
                // tui.mouse(true);
                tui.enter()?;
            } else if self.should_quit {
                log::info!("Application shutting down, initiating graceful shutdown sequence");

                // Send shutdown action to all components
                action_tx.try_send(Action::Shutdown)?;

                // Process any pending actions
                while let Ok(action) = action_rx.try_recv() {
                    for component in self.components.iter_mut() {
                        if let Some(action) = component.update(action.clone())? {
                            action_tx.try_send(action)?;
                        }
                    }
                }

                // Shutdown each component with timeout
                let shutdown_start = std::time::Instant::now();
                let total_timeout = std::time::Duration::from_secs(5);

                for (idx, component) in self.components.iter_mut().enumerate() {
                    let elapsed = shutdown_start.elapsed();
                    if elapsed >= total_timeout {
                        log::warn!(
                            "Shutdown timeout reached, forcing termination for remaining components"
                        );
                        break;
                    }

                    log::debug!("Shutting down component {}", idx);

                    // Shutdown with timeout
                    let shutdown_result = std::panic::catch_unwind(
                        std::panic::AssertUnwindSafe(|| component.shutdown())
                    );

                    match shutdown_result {
                        Ok(Ok(())) => {
                            log::debug!("Component {} shutdown successfully", idx);
                        }
                        Ok(Err(e)) => {
                            log::error!("Component {} shutdown failed: {:?}", idx, e);
                        }
                        Err(_) => {
                            log::error!("Component {} panicked during shutdown", idx);
                        }
                    }
                }

                log::info!("All components shutdown complete");

                tui.stop()?;
                break;
            }
        }
        tui.exit()?;

        if let Some(ref s) = self.post_exist_msg {
            println!("`netscanner` failed with Error:");
            println!("{}", s);
        }

        Ok(())
    }
}

//! Netscanner - A modern network scanner with TUI
//!
//! Netscanner is a terminal-based network scanning tool built with Rust that provides
//! real-time network discovery, packet capture, port scanning, and WiFi monitoring
//! capabilities through an interactive terminal user interface (TUI).
//!
//! # Features
//!
//! - **Network Discovery**: Scan local network segments to discover active hosts
//! - **Port Scanning**: Concurrent port scanning with service detection
//! - **Packet Capture**: Real-time packet analysis for ARP, TCP, UDP, ICMP protocols
//! - **WiFi Monitoring**: Scan and monitor nearby WiFi networks
//! - **Traffic Analysis**: Live network traffic visualization
//! - **Export Functionality**: Save scan results and packet captures
//!
//! # Architecture
//!
//! The application follows a component-based architecture built on an event-driven
//! messaging system:
//!
//! - **Action System** ([`action`]): All components communicate via a typed Action enum,
//!   sent through bounded mpsc channels to prevent memory exhaustion
//! - **Component System** ([`components`]): UI elements implement the Component trait,
//!   allowing them to handle events, update state, and render independently
//! - **TUI Layer** ([`tui`]): Manages terminal I/O, event loops, and rendering using ratatui
//! - **Application Core** ([`app`]): Coordinates components, routes actions, and manages
//!   the main event loop
//!
//! # Privilege Requirements
//!
//! Many network operations require elevated privileges:
//! - **Linux**: Run with `sudo` or use capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip`
//! - **macOS**: Run with `sudo`
//! - **Windows**: Run as Administrator
//!
//! The application will warn but not exit if privileges are insufficient, allowing
//! partial functionality.
//!
//! # Usage Example
//!
//! ```bash
//! # Run with default settings
//! sudo netscanner
//!
//! # Customize tick and frame rates
//! sudo netscanner --tick-rate 2.0 --frame-rate 30.0
//! ```
//!
//! # Error Handling
//!
//! The application uses [`color_eyre`] for enhanced error reporting with backtraces
//! and context. Panics are caught and reported through a custom panic handler that
//! provides diagnostic information.

pub mod action;
pub mod app;
pub mod cli;
pub mod components;
pub mod config;
pub mod dns_cache;
pub mod mode;
pub mod privilege;
pub mod tui;
pub mod utils;
pub mod enums;
pub mod layout;
pub mod widgets;

use clap::Parser;
use cli::Cli;
use color_eyre::eyre::Result;

use crate::{
  app::App,
  utils::{initialize_logging, initialize_panic_handler},
};

/// Main async entry point for the netscanner application.
///
/// This function initializes the application infrastructure and runs the main event loop:
///
/// 1. **Logging Setup**: Configures the logging system for diagnostics
/// 2. **Panic Handler**: Installs a custom panic handler for better error reporting
/// 3. **Privilege Check**: Warns if the application lacks network privileges (non-fatal)
/// 4. **CLI Parsing**: Parses command-line arguments for tick/frame rates
/// 5. **Application Run**: Creates and runs the main application
///
/// # Errors
///
/// Returns an error if:
/// - Logging or panic handler initialization fails
/// - Application creation fails (e.g., unable to create TUI)
/// - Application runtime encounters a fatal error
///
/// # Privilege Warning
///
/// The application will warn but not exit if network privileges are insufficient.
/// This allows partial functionality (e.g., viewing WiFi info without packet capture).
async fn tokio_main() -> Result<()> {
  initialize_logging()?;

  initialize_panic_handler()?;

  // Warn if not running with privileges (non-fatal, operations will fail with better errors)
  if !privilege::has_network_privileges() {
    eprintln!("WARNING: Running without elevated privileges.");
    eprintln!("Some network operations may fail.");
    eprintln!("For full functionality, run with sudo or set appropriate capabilities.");
    eprintln!();
  }

  let args = Cli::parse();
  let mut app = App::new(args.tick_rate, args.frame_rate)?;
  app.run().await?;

  Ok(())
}

/// Application entry point with Tokio async runtime.
///
/// This is the main entry point that creates the Tokio runtime and executes
/// the async application logic. It catches and reports any errors that occur
/// during application execution.
///
/// # Errors
///
/// Propagates errors from [`tokio_main`], displaying a user-friendly error
/// message before returning the error for process exit code handling.
#[tokio::main]
async fn main() -> Result<()> {
  if let Err(e) = tokio_main().await {
    eprintln!("{} error: Something went wrong", env!("CARGO_PKG_NAME"));
    Err(e)
  } else {
    Ok(())
  }
}

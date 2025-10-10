//! Action-based messaging system for component communication.
//!
//! This module defines the [`Action`] enum, which is the central messaging
//! mechanism for the entire application. All components communicate by sending
//! and receiving Actions through bounded mpsc channels.
//!
//! # Design Philosophy
//!
//! The action system implements a **unidirectional data flow** pattern:
//! - Components never call each other directly
//! - All state changes flow through Action messages
//! - Actions are processed in a central event loop
//! - This enables loose coupling and testability
//!
//! # Action Categories
//!
//! Actions are organized into several categories:
//!
//! ## System Actions
//! - **Lifecycle**: `Tick`, `Render`, `Quit`, `Shutdown`, `Suspend`, `Resume`
//! - **UI**: `Resize`, `Refresh`, `Error`
//!
//! ## Navigation Actions
//! - **Movement**: `Up`, `Down`, `Left`, `Right`
//! - **Tabs**: `Tab`, `TabChange`
//! - **Modes**: `AppModeChange`, `ModeChange`
//!
//! ## Network Actions
//! - **Discovery**: `ScanCidr`, `PingIp`, `CountIp`, `CidrError`
//! - **Ports**: `PortScan`, `PortScanDone`
//! - **Packets**: `PacketDump`, `ArpRecieve`
//! - **WiFi**: `Scan`
//! - **DNS**: `DnsResolved`
//!
//! ## Data Actions
//! - **Export**: `Export`, `ExportData`
//! - **Interface**: `ActiveInterface`, `InterfaceSwitch`
//! - **Toggles**: `GraphToggle`, `DumpToggle`, `Clear`
//!
//! # Message Flow Example
//!
//! ```text
//! User presses 's' key to scan
//!     │
//!     ▼
//! Key event → Action::ScanCidr
//!     │
//!     ▼
//! Ports component receives Action::ScanCidr
//!     │
//!     ▼
//! Spawns async port scan tasks
//!     │
//!     ▼
//! Each open port → Action::PortScan(index, port)
//!     │
//!     ▼
//! Ports component stores result
//!     │
//!     ▼
//! When complete → Action::PortScanDone(index)
//! ```
//!
//! # Serialization
//!
//! Actions can be deserialized from strings for use in configuration files
//! (keybindings). This allows user-configurable keyboard shortcuts.
//!
//! Example: `"Scan"` → `Action::ScanCidr`

use chrono::{DateTime, Local};
use pnet::datalink::NetworkInterface;
use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize,
};
use std::fmt;

use crate::{
    components::{packetdump::ArpPacketData, wifi_scan::WifiInfo},
    enums::{ExportData, PacketTypeEnum, PacketsInfoTypesEnum, TabsEnum},
    mode::Mode,
};

/// Actions represent all possible messages that can flow through the application.
///
/// Components send Actions to communicate state changes, trigger operations,
/// or notify other components of events. Actions are processed in the main
/// event loop and routed to all components via their `update()` method.
///
/// # Implementation Note
///
/// `PartialEq` is implemented to allow action comparison in tests and for
/// filtering (e.g., skipping debug logs for Tick/Render actions).
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Logic update tick - sent at tick_rate Hz
    Tick,
    /// Render frame - sent at frame_rate Hz
    Render,
    /// Terminal resized to new dimensions (width, height)
    Resize(u16, u16),
    /// Suspend application (Unix SIGTSTP)
    Suspend,
    /// Resume after suspension
    Resume,
    /// Request graceful shutdown
    Quit,
    /// Begin shutdown sequence for all components
    Shutdown,
    /// Refresh UI (currently unused)
    Refresh,
    /// Fatal error occurred, display message and quit
    Error(String),
    /// Show help information (currently unused)
    Help,

    // -- Navigation and UI actions
    /// Move selection up in lists
    Up,
    /// Move selection down in lists
    Down,
    /// Navigate left (currently unused)
    Left,
    /// Navigate right (currently unused)
    Right,
    /// Cycle to next tab
    Tab,
    /// Jump to specific tab
    TabChange(TabsEnum),
    /// Toggle graph visibility in WiFi view
    GraphToggle,
    /// Toggle packet dump display
    DumpToggle,
    /// Switch to next network interface
    InterfaceSwitch,

    // -- Network discovery and scanning
    /// Start CIDR network scan (triggered by 's' key)
    ScanCidr,
    /// Set the active network interface for capture
    ActiveInterface(NetworkInterface),
    /// ARP packet received (from packet capture)
    ArpRecieve(ArpPacketData),
    /// WiFi scan results ready
    Scan(Vec<WifiInfo>),

    // -- Application modes
    /// Change application-wide input mode
    AppModeChange(Mode),
    /// Change component-specific mode
    ModeChange(Mode),

    // -- Host discovery
    /// Ping response received for IP address
    PingIp(String),
    /// Count discovered IPs (currently unused)
    CountIp,
    /// Invalid CIDR notation entered
    CidrError,
    /// DNS reverse lookup completed (IP, Hostname)
    DnsResolved(String, String),

    // -- Packet capture
    /// New packet captured (time, packet data, type)
    PacketDump(DateTime<Local>, PacketsInfoTypesEnum, PacketTypeEnum),

    // -- Port scanning
    /// Open port discovered (IP index, port number)
    PortScan(usize, u16),
    /// Port scan completed for IP at index
    PortScanDone(usize),

    // -- Data management
    /// Clear captured data
    Clear,
    /// Begin export sequence
    Export,
    /// Export data ready for writing
    ExportData(ExportData),
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ActionVisitor;

        impl<'de> Visitor<'de> for ActionVisitor {
            type Value = Action;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid string representation of Action")
            }

            fn visit_str<E>(self, value: &str) -> Result<Action, E>
            where
                E: de::Error,
            {
                match value {
                    // -- custom actions
                    "InputMode" => Ok(Action::ModeChange(Mode::Input)),
                    "NormalMode" => Ok(Action::ModeChange(Mode::Normal)),
                    "Graph" => Ok(Action::GraphToggle),
                    "Dump" => Ok(Action::DumpToggle),
                    "Interface" => Ok(Action::InterfaceSwitch),
                    "Scan" => Ok(Action::ScanCidr),
                    "Clear" => Ok(Action::Clear),
                    "Up" => Ok(Action::Up),
                    "Down" => Ok(Action::Down),
                    "Left" => Ok(Action::Left),
                    "Right" => Ok(Action::Right),
                    "Tab" => Ok(Action::Tab),
                    "Export" => Ok(Action::Export),
                    "JumpDiscovery" => Ok(Action::TabChange(TabsEnum::Discovery)),
                    "JumpPackets" => Ok(Action::TabChange(TabsEnum::Packets)),
                    "JumpPorts" => Ok(Action::TabChange(TabsEnum::Ports)),
                    "JumpSniffer" => Ok(Action::TabChange(TabsEnum::Traffic)),

                    // -- default actions
                    "Tick" => Ok(Action::Tick),
                    "Render" => Ok(Action::Render),
                    "Suspend" => Ok(Action::Suspend),
                    "Resume" => Ok(Action::Resume),
                    "Quit" => Ok(Action::Quit),
                    "Refresh" => Ok(Action::Refresh),
                    "Help" => Ok(Action::Help),
                    data if data.starts_with("Error(") => {
                        let error_msg = data.trim_start_matches("Error(").trim_end_matches(')');
                        Ok(Action::Error(error_msg.to_string()))
                    }
                    data if data.starts_with("Resize(") => {
                        let parts: Vec<&str> = data
                            .trim_start_matches("Resize(")
                            .trim_end_matches(')')
                            .split(',')
                            .collect();
                        if parts.len() == 2 {
                            let width: u16 = parts[0].trim().parse().map_err(E::custom)?;
                            let height: u16 = parts[1].trim().parse().map_err(E::custom)?;
                            Ok(Action::Resize(width, height))
                        } else {
                            Err(E::custom(format!("Invalid Resize format: {}", value)))
                        }
                    }
                    _ => Err(E::custom(format!("Unknown Action variant: {}", value))),
                }
            }
        }

        deserializer.deserialize_str(ActionVisitor)
    }
}

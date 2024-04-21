use chrono::{DateTime, Local};
use pnet::datalink::NetworkInterface;
use pnet::util::MacAddr;
use ratatui::text::Line;
use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize, Serialize,
};
use std::{fmt, net::Ipv4Addr};

use crate::{
    components::{packetdump::ArpPacketData, wifi_scan::WifiInfo},
    enums::{PacketTypeEnum, PacketsInfoTypesEnum},
    mode::Mode,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    Refresh,
    Error(String),
    Help,

    // -- custom actions
    Up,
    Down,
    Left,
    Right,
    GraphToggle,
    PacketToggle,
    DumpToggle,
    InterfaceSwitch,
    ScanCidr,
    ActiveInterface(NetworkInterface),
    ArpRecieve(ArpPacketData),
    Scan(Vec<WifiInfo>),
    ModeChange(Mode),
    PingIp(String),
    CountIp,
    CidrError,
    PacketDump(DateTime<Local>, PacketsInfoTypesEnum, PacketTypeEnum),
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
                    "Packets" => Ok(Action::PacketToggle),
                    "Dump" => Ok(Action::DumpToggle),
                    "Interface" => Ok(Action::InterfaceSwitch),
                    "Scan" => Ok(Action::ScanCidr),
                    "Up" => Ok(Action::Up),
                    "Down" => Ok(Action::Down),
                    "Left" => Ok(Action::Left),
                    "Right" => Ok(Action::Right),

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

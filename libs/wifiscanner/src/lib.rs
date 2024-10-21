// Copyright 2016 Mark Sta Ana.
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0>, at your option.
// This file may not be copied, modified, or distributed except
// according to those terms.

// Inspired by Maurice Svay's node-wifiscanner (https://github.com/mauricesvay/node-wifiscanner)

//! A crate to list WiFi hotspots in your area.
//!
//! As of v0.5.x now supports macOS, Linux and Windows. :tada:
//!
//! # Usage
//!
//! This crate is on [crates.io](https://crates.io/crates/tokio-wifiscanner) and can be
//! used by adding `tokio-wifiscanner` to the dependencies in your project's `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! tokio-wifiscanner = "0.2.*"
//! ```
//!
//! and this to your crate root:
//!
//! ```rust
//! extern crate tokio_wifiscanner;
//! ```
//!
//! # Example
//!
//! ```
//!#[tokio::main(flavor = "current_thread")]
//!async fn main() {
//!    let networks = tokio_wifiscanner::scan().await.expect("Cannot scan network");
//!    for network in networks {
//!        println!(
//!            "{} {:15} {:10} {:4} {}",
//!            network.mac, network.ssid, network.channel, network.signal_level, network.security
//!        );
//!    }
//!}
//! ```
//!
//! Alternatively if you've cloned the the Git repo, you can run the above examples
//! using: `cargo run --example scan`.

//TODO need to find a way to move these out of lib and into sys or better still windows module
#[cfg(target_os = "windows")]
#[macro_use]
extern crate itertools;
#[cfg(target_os = "windows")]
extern crate regex;

mod sys;

use std::fmt;
use std::process::ExitStatus;

type Result<T> = std::result::Result<T, Error>;

#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SyntaxRegexError,
    CommandNotFound,
    CommandFailed(ExitStatus, String),
    NoMatch,
    FailedToParse,
    NoValue,
    HeaderNotFound(&'static str),
}

/// Wifi struct used to return information about wifi hotspots
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Wifi {
    /// mac address
    pub mac: String,
    /// hotspot name
    pub ssid: String,
    pub channel: String,
    /// wifi signal strength in dBm
    pub signal_level: String,
    /// this field is currently empty in the Linux version of the lib
    pub security: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::SyntaxRegexError => write!(f, "An error occured during syntax check"),
            Error::CommandNotFound => write!(f, "Couldn't find command"),
            Error::CommandFailed(status, reason) => {
                write!(f, "Command failed with exit status {}: {}", status, reason)
            }
            Error::NoMatch => write!(f, "Couldn't match"),
            Error::FailedToParse => write!(f, "Failed to parse command"),
            Error::NoValue => write!(f, "Value expected but is not present"),
            Error::HeaderNotFound(header) => {
                write!(f, "Did not find header {} but expected it", header)
            }
        }
    }
}

impl std::error::Error for Error {}

/// Returns a list of WiFi hotspots in your area.
/// Uses `airport` on macOS and `iw` on Linux.
pub async fn scan() -> Result<Vec<Wifi>> {
    crate::sys::scan().await
}

use crate::{Error, Result, Wifi};
use regex::Regex;
use std::vec::Vec;
use tokio::process::Command;

/// Returns a list of WiFi hotspots in your area - (Windows) uses `netsh`
pub async fn scan() -> Result<Vec<Wifi>> {
    let output = Command::new("netsh.exe")
        .args(&["wlan", "show", "networks", "mode=Bssid"])
        .output()
        .await
        .map_err(|_| Error::CommandNotFound)?;
    let data = String::from_utf8_lossy(&output.stdout);
    parse_netsh(&data)
}

fn parse_netsh(network_list: &str) -> Result<Vec<Wifi>> {
    let mut wifis = Vec::new();

    // Regex for matching SSID and MAC (BSSID)
    let ssid_regex = Regex::new(r"SSID\s\d+\s:\s(.+)").map_err(|_| Error::SyntaxRegexError)?;
    let mac_regex = Regex::new(r"BSSID\s\d+\s+:\s([a-fA-F0-9:]{17})").map_err(|_| Error::SyntaxRegexError)?;
    let signal_regex = Regex::new(r"Signal\s+:\s(\d+)%").map_err(|_| Error::SyntaxRegexError)?;
    let channel_regex = Regex::new(r"Channel\s+:\s(\d+)").map_err(|_| Error::SyntaxRegexError)?;
    let security_regex = Regex::new(r"Authentication\s+:\s(.+)").map_err(|_| Error::SyntaxRegexError)?;

    // Split the output by SSID entries
    for block in network_list.split("\r\n\r\n") {
        let mut wifi_macs = Vec::new();
        let mut wifi_ssid = String::new();
        let mut wifi_channels = Vec::new();
        let mut wifi_rssi = Vec::new();
        let mut wifi_security = String::new();

        // Match each line with appropriate regex
        for line in block.lines() {
            if let Some(captures) = ssid_regex.captures(line) {
                wifi_ssid = captures[1].trim().to_string();
            }
            if let Some(captures) = mac_regex.captures(line) {
                wifi_macs.push(captures[1].trim().to_string());
            }
            if let Some(captures) = signal_regex.captures(line) {
                let signal_percent = captures[1].trim().parse::<i32>().unwrap_or(0);
                let rssi = (signal_percent as f32 / 2.0 - 100.0) as i32; // Convert signal % to dBm
                wifi_rssi.push(rssi);
            }
            if let Some(captures) = channel_regex.captures(line) {
                wifi_channels.push(captures[1].trim().to_string());
            }
            if let Some(captures) = security_regex.captures(line) {
                wifi_security = captures[1].trim().to_string();
            }
        }

        // Create Wifi struct for each MAC (BSSID) found
        for (mac, channel, rssi) in izip!(wifi_macs, wifi_channels, wifi_rssi) {
            wifis.push(Wifi {
                mac,
                ssid: wifi_ssid.clone(),
                channel,
                signal_level: rssi.to_string(),
                security: wifi_security.clone(),
            });
        }
    }

    Ok(wifis)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn should_parse_netsh() {
        use std::fs;

        // Note: formula for % to dBm is (% / 100) - 100
        let expected = vec![
            Wifi {
                mac: "ab:cd:ef:01:23:45".to_string(),
                ssid: "Vodafone Hotspot".to_string(),
                channel: "6".to_string(),
                signal_level: "-92".to_string(),
                security: "Open".to_string(),
            },
            Wifi {
                mac: "ab:cd:ef:01:23:45".to_string(),
                ssid: "Vodafone Hotspot".to_string(),
                channel: "6".to_string(),
                signal_level: "-73".to_string(),
                security: "Open".to_string(),
            },
            Wifi {
                mac: "ab:cd:ef:01:23:45".to_string(),
                ssid: "EdaBox".to_string(),
                channel: "11".to_string(),
                signal_level: "-82".to_string(),
                security: "WPA2-Personal".to_string(),
            },
            Wifi {
                mac: "ab:cd:ef:01:23:45".to_string(),
                ssid: "FRITZ!Box 2345 Cable".to_string(),
                channel: "1".to_string(),
                signal_level: "-50".to_string(),
                security: "WPA2-Personal".to_string(),
            },
        ];

        // Load test fixtures
        let fixture = fs::read_to_string("tests/fixtures/netsh/netsh01_windows81.txt").unwrap();

        let result = parse_netsh(&fixture).unwrap();
        assert_eq!(expected[0], result[0]);
        assert_eq!(expected[1], result[1]);
        assert_eq!(expected[2], result[2]);
        assert_eq!(expected[3], result[3]);
    }
}

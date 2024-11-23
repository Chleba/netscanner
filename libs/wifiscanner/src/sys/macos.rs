use crate::{Error, Result, Wifi};
use os_version::{self, MacOS};
use regex::Regex;
use tokio::process::Command;
use version_compare::{compare_to, Cmp};

/// Returns a list of WiFi hotspots in your area - (OSX/MacOS) uses `airport`
pub(crate) async fn scan() -> Result<Vec<Wifi>> {
    let mac_version = match os_version::MacOS::detect() {
        Ok(version) => version,
        Err(_) => MacOS {
            version: "0.0.0".to_string(),
        },
    };

    let r = match compare_to(mac_version.version, "14.4", Cmp::Ge) {
        Ok(cmp) => {
            if cmp {
                scan_system_profile().await
            } else {
                scan_airport().await
            }
        }
        Err(_) => scan_airport().await,
    };

    return r;
}

async fn scan_system_profile() -> Result<Vec<Wifi>> {
    let output = Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
        .await
        .map_err(|_| Error::CommandNotFound)?;
    let data = String::from_utf8_lossy(&output.stdout);
    parse_system_profile(&data)
}

fn parse_system_profile(network_list: &str) -> Result<Vec<Wifi>> {
    let mut wifis: Vec<Wifi> = Vec::new();

    let re = Regex::new(r"(?m)^\s+([^\n]+):\n\s+PHY Mode: [^\n]+\n\s+Channel: ([^\n]+)\n\s+.*?\n\s+Security: ([^\n]+)\n\s+Signal / Noise: ([^\n]+)")
        .unwrap();
    for w in re.captures_iter(network_list) {

        let ssid = w[1].trim().to_string();
        let channel = w[2].split('(').next().unwrap().trim().to_string();
        let security = w[3].trim().to_string();
        let signal = w[4].split('/').next().unwrap().trim().to_string();

        let wifi = Wifi{
            ssid,
            channel,
            signal_level: signal.split(' ').next().unwrap().trim().to_string(),
            security,
            mac: String::new(),
        };
        wifis.push(wifi);
    }

    Ok(wifis)
}

async fn scan_airport() -> Result<Vec<Wifi>> {
    let output = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.\
         framework/Versions/Current/Resources/airport",
    )
    .arg("-s")
    .output()
    .await
    .map_err(|_| Error::CommandNotFound)?;

    let data = String::from_utf8_lossy(&output.stdout);

    parse_airport(&data)
}

fn parse_airport(network_list: &str) -> Result<Vec<Wifi>> {
    let mut wifis: Vec<Wifi> = Vec::new();
    let mut lines = network_list.lines();
    let headers = match lines.next() {
        Some(v) => v,
        // return an empty list of WiFi if the network_list is empty
        None => return Ok(vec![]),
    };

    let headers_string = String::from(headers);
    let col_headers = ["BSSID", "RSSI", "CHANNEL", "HT", "SECURITY"]
        .iter()
        .map(|header| {
            headers_string
                .find(header)
                .ok_or(Error::HeaderNotFound(header))
        })
        .collect::<Result<Vec<_>>>()?;
    let col_mac = col_headers[0];
    let col_rrsi = col_headers[1];
    let col_channel = col_headers[2];
    let col_ht = col_headers[3];
    let col_security = col_headers[4];

    for line in lines {
        let ssid = &line[..col_mac].trim();
        let mac = &line[col_mac..col_rrsi].trim();
        let signal_level = &line[col_rrsi..col_channel].trim();
        let channel = &line[col_channel..col_ht].trim();
        let security = &line[col_security..].trim();

        wifis.push(Wifi {
            mac: mac.to_string(),
            ssid: ssid.to_string(),
            channel: channel.to_string(),
            signal_level: signal_level.to_string(),
            security: security.to_string(),
        });
    }

    Ok(wifis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn should_parse_airport() {
        let mut expected: Vec<Wifi> = Vec::new();
        expected.push(Wifi {
            mac: "00:35:1a:90:56:03".to_string(),
            ssid: "OurTest".to_string(),
            channel: "112".to_string(),
            signal_level: "-70".to_string(),
            security: "WPA2(PSK/AES/AES)".to_string(),
        });

        expected.push(Wifi {
            mac: "00:35:1a:90:56:00".to_string(),
            ssid: "TEST-Wifi".to_string(),
            channel: "1".to_string(),
            signal_level: "-67".to_string(),
            security: "WPA2(PSK/AES/AES)".to_string(),
        });

        let path = PathBuf::from("tests/fixtures/airport/airport01.txt");

        let file_path = path.as_os_str();

        let mut file = File::open(&file_path).unwrap();

        let mut filestr = String::new();
        let _ = file.read_to_string(&mut filestr).unwrap();

        let result = parse_airport(&filestr).unwrap();
        let last = result.len() - 1;
        assert_eq!(expected[0], result[0]);
        assert_eq!(expected[1], result[last]);
    }

    #[test]
    fn should_not_parse_other() {
        let path = PathBuf::from("tests/fixtures/iw/iw_dev_01.txt");
        let file_path = path.as_os_str();
        let mut file = File::open(&file_path).unwrap();
        let mut filestr = String::new();
        file.read_to_string(&mut filestr).unwrap();

        assert_eq!(
            parse_airport(&filestr).err().unwrap(),
            Error::HeaderNotFound("BSSID")
        );
    }
}

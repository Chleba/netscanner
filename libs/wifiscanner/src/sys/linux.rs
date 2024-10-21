use crate::{Error, Result, Wifi};
use std::env;

/// Returns a list of WiFi hotspots in your area - (Linux) uses `iw`
pub(crate) async fn scan() -> Result<Vec<Wifi>> {
    use tokio::process::Command;
    const PATH_ENV: &'static str = "PATH";
    let path_system = "/usr/sbin:/sbin";
    let path = env::var_os(PATH_ENV).map_or(path_system.to_string(), |v| {
        format!("{}:{}", v.to_string_lossy().into_owned(), path_system)
    });

    let output = Command::new("iw")
        .env(PATH_ENV, path.clone())
        .arg("dev")
        .output().await
        .map_err(|_| Error::CommandNotFound)?;
    let data = String::from_utf8_lossy(&output.stdout);
    let interface = parse_iw_dev(&data)?;

    let output = Command::new("iw")
        .env(PATH_ENV, path)
        .arg("dev")
        .arg(interface)
        .arg("scan")
        .output()
        .await
        .map_err(|_| Error::CommandNotFound)?;
    if !output.status.success() {
        return Err(Error::CommandFailed(
            output.status,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let data = String::from_utf8_lossy(&output.stdout);
    parse_iw_dev_scan(&data)
}

fn parse_iw_dev(interfaces: &str) -> Result<String> {
    interfaces
        .split("\tInterface ")
        .take(2)
        .last()
        .ok_or(Error::NoValue)?
        .split("\n")
        .nth(0)
        .ok_or(Error::NoValue)
        .map(|text| text.to_string())
}

fn parse_iw_dev_scan(network_list: &str) -> Result<Vec<Wifi>> {
    // TODO: implement wifi.security
    let mut wifis: Vec<Wifi> = Vec::new();
    let mut wifi = Wifi::default();
    for line in network_list.split("\n") {
        if let Ok(mac) = extract_value(line, "BSS ", Some("(")) {
            wifi.mac = mac;
        } else if let Ok(signal) = extract_value(line, "\tsignal: ", Some(" dBm")) {
            wifi.signal_level = signal;
        } else if let Ok(channel) = extract_value(line, "\tDS Parameter set: channel ", None) {
            wifi.channel = channel;
        } else if let Ok(ssid) = extract_value(line, "\tSSID: ", None) {
            wifi.ssid = ssid;
        }

        if !wifi.mac.is_empty()
            && !wifi.signal_level.is_empty()
            && !wifi.channel.is_empty()
            && !wifi.ssid.is_empty()
        {
            wifis.push(wifi);
            wifi = Wifi::default();
        }
    }

    Ok(wifis)
}

fn extract_value(line: &str, pattern_start: &str, pattern_end: Option<&str>) -> Result<String> {
    let start = pattern_start.len();
    if start < line.len() && &line[0..start] == pattern_start {
        let end = match pattern_end {
            Some(end) => line.find(end).ok_or(Error::NoValue)?,
            None => line.len(),
        };
        Ok(line[start..end].to_string())
    } else {
        Err(Error::NoValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn should_parse_iw_dev() {
        let expected = "wlp2s0";

        // FIXME: should be a better way to create test fixtures
        let mut path = PathBuf::new();
        path.push("tests");
        path.push("fixtures");
        path.push("iw");
        path.push("iw_dev_01.txt");

        let file_path = path.as_os_str();

        let mut file = File::open(&file_path).unwrap();

        let mut filestr = String::new();
        let _ = file.read_to_string(&mut filestr).unwrap();

        let result = parse_iw_dev(&filestr).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn should_parse_iw_dev_scan() {
        let mut expected: Vec<Wifi> = Vec::new();
        expected.push(Wifi {
            mac: "11:22:33:44:55:66".to_string(),
            ssid: "hello".to_string(),
            channel: "10".to_string(),
            signal_level: "-67.00".to_string(),
            security: "".to_string(),
        });

        expected.push(Wifi {
            mac: "66:77:88:99:aa:bb".to_string(),
            ssid: "hello-world-foo-bar".to_string(),
            channel: "8".to_string(),
            signal_level: "-89.00".to_string(),
            security: "".to_string(),
        });

        // FIXME: should be a better way to create test fixtures
        let mut path = PathBuf::new();
        path.push("tests");
        path.push("fixtures");
        path.push("iw");
        path.push("iw_dev_scan_01.txt");

        let file_path = path.as_os_str();

        let mut file = File::open(&file_path).unwrap();

        let mut filestr = String::new();
        let _ = file.read_to_string(&mut filestr).unwrap();

        let result = parse_iw_dev_scan(&filestr).unwrap();
        assert_eq!(expected[0], result[0]);
        assert_eq!(expected[1], result[5]);
    }
}

```
             _                                       
            | |                                      
  _ __   ___| |_ ___  ___ __ _ _ __  _ __   ___ _ __ 
 | '_ \ / _ \ __/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 | | | |  __/ |_\__ \ (_| (_| | | | | | | |  __/ |   
 |_| |_|\___|\__|___/\___\__,_|_| |_|_| |_|\___|_|
```                                                  
***
<img src='./demo.gif' width='550px'/>

[![Arch package](https://repology.org/badge/version-for-repo/arch/netscanner.svg)](https://repology.org/project/netscanner/versions)
[![Alpine Linux Edge package](https://repology.org/badge/version-for-repo/alpine_edge/netscanner.svg)](https://repology.org/project/netscanner/versions)
[![nixpkgs stable 24.05 package](https://repology.org/badge/version-for-repo/nix_stable_24_05/netscanner.svg)](https://repology.org/project/netscanner/versions)
[![Manjaro Stable package](https://repology.org/badge/version-for-repo/manjaro_stable/netscanner.svg)](https://repology.org/project/netscanner/versions)
[![Kali Linux Rolling package](https://repology.org/badge/version-for-repo/kali_rolling/netscanner.svg)](https://repology.org/project/netscanner/versions)

`netscanner` - Network scanning & diagnostic tool.

**FEATURES:**
- [x] List HW Interfaces
- [x] Switching active Interface for scanning & packet-dumping
- [x] WiFi networks scanning
- [x] WiFi signals strength (with charts)
- [x] (IPv4) Pinging CIDR with hostname, oui & mac address
- [x] (IPv4) Packetdump (TCP, UDP, ICMP, ARP)
- [x] (IPv6) Packetdump (ICMP6)
- [x] start/pause packetdump
- [x] scanning open ports (TCP)
- [x] packet logs filter
- [x] export scanned ips, ports into csv

**TODO:**
- [ ] ipv6 scanning & dumping
- [ ] export scanned packets into csv files

## *Notes*:
- Must be run with root privileges. 
- After `cargo install` You may try to change binary file chown & chmod
```
sudo chown root:user /home/user/.cargo/bin/netscanner
sudo chmod u+s /home/user/.cargo/bin/netscanner
```

## Install on `Arch Linux`
```
pacman -S netscanner
```

## Install on `Alpine(edge) Linux`
```
apk add netscanner --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
```

## Install with `cargo`
```
cargo install netscanner
```
## Appreciation
`netscanner` has been made thanks to some awesome libraries that can be found in [Cargo.toml](./Cargo.toml) file.
But mostly I would like to link these two libraries that help me the most:
- Ratatui: [https://github.com/ratatui-org/ratatui](https://github.com/ratatui-org/ratatui)
- libpnet: [https://github.com/libpnet/libpnet](https://github.com/libpnet/libpnet)

> Created by: Lukas Chleba <chlebik@gmail.com>

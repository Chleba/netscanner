# netscanner


Network scanning tool with features like:

- List Interfaces
- WiFi scanning
- WiFi signal strength (with chart)
- Ping CIDR with hostname, oui & mac address
- packetdump (TCP, UDP, ICMP, ARP)

must be run with sudo priviliges

## Install `Arch AUR`
```
paru -S netscanner
```

## Install via Cargo
```
cargo install netscanner
```
*Note:* After cargo install You may try change binary file chown & chmod like this:
```
sudo chown root:user /home/user/.cargo/bin/netscanner
sudo chmod u+s /home/user/.cargo/bin/netscanner
```

![netscanner screenshot](./netscanner.png?raw=true)
![netscanner screenshot](./netscanner1.png?raw=true)

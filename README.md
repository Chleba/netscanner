# netscanner


Network scanning tool with features like:

- List Interfaces
- WiFi scanning
- WiFi signal strength (with chart)
- Ping CIDR with hostname, oui & mac address
- packetdump (TCP, UDP, ICMP, ARP)

Must be run with root privileges. 

## Install `Arch AUR`
```
paru -S netscanner
```
or
```
yay -S netscanner-bin
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

## TODO
- [ ] scanning open ports
- [ ] modal window with packet data
- [ ] ipv6 scanning & dumping

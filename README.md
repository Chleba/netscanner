# netscanner


Network scanning tool with features like:

- [x] List HW Interfaces
- [x] Switching active Interface for scanning & packet-dumping
- [x] WiFi networks scanning
- [x] WiFi signals strength (with charts)
- [x] (IPv4) Pinging CIDR with hostname, oui & mac address
- [x] (IPv4) Packetdump (TCP, UDP, ICMP, ARP)

**TODO:**
- [ ] scanning open ports
- [ ] modal window with packet data
- [ ] ipv6 scanning & dumping

## *Notes*:
- Must be run with root privileges. 
- After `cargo install` You may try to change binary file chown & chmod
```
sudo chown root:user /home/user/.cargo/bin/netscanner
sudo chmod u+s /home/user/.cargo/bin/netscanner
```

## Install `Arch AUR`
```
paru -S netscanner
```
```
yay -S netscanner-bin
```

## Install `Cargo`
```
cargo install netscanner
```

![netscanner screenshot](./netscanner.png?raw=true)
![netscanner screenshot](./netscanner1.png?raw=true)

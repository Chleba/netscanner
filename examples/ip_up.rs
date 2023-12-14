use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pnet::datalink::{self, NetworkInterface, MacAddr, Channel};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherType};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;

fn main() {
    let target_ip = "192.168.1.97"; // Replace with the IP address of the host you want to check

    if let Some(interface) = get_default_interface() {
        match send_icmp_request(&interface, target_ip) {
            Ok(_) => {
                println!("Host is up");
            }
            Err(e) => {
                eprintln!("Host is down: {}", e);
            }
        }
    } else {
        eprintln!("No suitable network interface found");
    }
}

fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.is_running())
}

fn send_icmp_request(interface: &NetworkInterface, target_ip: &str) -> Result<(), String> {
    let t_ip: Ipv4Addr = target_ip.parse::<Ipv4Addr>().unwrap();
    println!("{:?}", interface);
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .ok_or("No IPv4 address found for the interface")?;
    let source_mac = interface.mac.unwrap_or_default();

    // let mut packet = Vec::with_capacity(42);
    // let mut packet: Vec<u8> = vec![0; 42];
    let mut packet = [0u8; 42];
    match source_ip {
        IpAddr::V4(source_ip) => {
            let mut eth_packet = MutableEthernetPacket::new(&mut packet).unwrap();
            
            eth_packet.set_destination(source_mac::broadcast());
            eth_packet.set_source(MacAddr::broadcast());
            eth_packet.set_ethertype(EtherType::Arp)



                // MutableIpv4Packet::new(&mut packet).ok_or("Failed to create IPv4 packet")?;
            // ipv4_packet.set_version(4);
            // ipv4_packet.set_header_length(5);
            // ipv4_packet.set_total_length(42);
            // ipv4_packet.set_identification(42);
            // ipv4_packet.set_ttl(64);
            // ipv4_packet.set_destination(
            //     t_ip
            //     // Ipv4Addr::from_str(target_ip).map_err(|_| "Invalid target IP address")?,
            // );
            // ipv4_packet.set_source(source_ip as Ipv4Addr);
            // ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);

            let mut icmp_packet = MutableEchoRequestPacket::new(ipv4_packet.payload_mut())
                .ok_or("Failed to create ICMP packet")?;
            icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
            icmp_packet.set_identifier(42);
            icmp_packet.set_sequence_number(42);
        }
        IpAddr::V6(source_ip) => ()
    }

    // let mut tx = pnet::datalink::channel(&interface, Default::default()).unwrap();
    let (mut tx, _) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unkown channel"),
        Err(e) => panic!("error channel: {}", e),
    };

    // let (mut tx, _) = pnet::datalink::channel(&interface, Default::default())
    //     .map_err(|e| format!("Error creating channel: {:?}", e))?;

    // tx.send_to(packet.as_slice(), Some(source_mac))
    //     .map_err(|e| format!("Error sending packet: {:?}", e))?;

    let _ = tx.send_to(packet.as_slice(), None).expect("failed send packet");
        // .map_err(|e| format!("Error sending packet: {:?}", e))?;

    Ok(())
}

use cidr::Ipv4Cidr;
use std::net::Ipv4Addr;

fn main() {
    let cidr_range = "192.168.1.0/24"; // Replace with your CIDR range
    match cidr_range.parse::<Ipv4Cidr>() {
        Ok(ip_cidr) => {
            for ip in ip_cidr.iter() {
                println!("IP Address: {}", ip);
            }
        }
        Err(e) => {
            eprintln!("Error parsing CIDR range: {}", e);
        }
    }
}

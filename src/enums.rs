use pnet::packet::icmp::IcmpType;
use strum::{Display, EnumCount, EnumIter, FromRepr};

pub struct UDPPacketInfo {
    interface_name: String,
    source: String,
    source_port: String,
    destination: String,
    destination_port: String,
    length: String,
}

pub struct TCPPacketInfo {
    interface_name: String,
    source: String,
    source_port: String,
    destination: String,
    destination_port: String,
    length: String,
}

pub struct ARPPacketInfo {
    interface_name: String,
    source_mac: String,
    source_ip: String,
    destination_mac: String,
    destination_ip: String,
    operation: String,
}

pub struct ICMPPacketInfo {
    interface_name: String,
    source: String,
    destination: String,
    operation: String,
    icmp_type: IcmpType,
}

pub enum PacketsInfoTypesEnum {
    Arp(ARPPacketInfo),
    Tcp(TCPPacketInfo),
    Udp(UDPPacketInfo),
    Icmp(ICMPPacketInfo),
}

#[derive(Default, Clone, Copy, Display, FromRepr, EnumIter, EnumCount, PartialEq, Debug)]
pub enum PacketTypeEnum {
    #[default]
    #[strum(to_string = "All")]
    All,
    #[strum(to_string = "ARP")]
    Arp,
    #[strum(to_string = "TCP")]
    Tcp,
    #[strum(to_string = "UDP")]
    Udp,
    #[strum(to_string = "ICMP")]
    Icmp,
}

impl PacketTypeEnum {
    pub fn previous(&self) -> Self {
        let current_index: usize = *self as usize;
        let previous_index = current_index.saturating_sub(1);
        Self::from_repr(previous_index).unwrap_or(*self)
    }

    pub fn next(&self) -> Self {
        let current_index = *self as usize;
        let next_index = current_index.saturating_add(1);
        Self::from_repr(next_index).unwrap_or(*self)
    }
}


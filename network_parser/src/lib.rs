pub mod error;
pub mod ethernet;
pub mod ipv4;
pub mod udp;

use error::ParseError;
use ethernet::EthernetHeader;
use ipv4::Ipv4Packet;
use udp::UdpDatagram;

pub struct Packet<'a> {
    pub ethernet: EthernetHeader<'a>,
    pub ipv4: Option<Ipv4Packet<'a>>,
    pub udp: Option<UdpDatagram<'a>>,
}

pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, ParseError> {
    let (ethernet, rest) = EthernetHeader::parse_ethernet(data)?;
    let (ipv4, rest) = match Ipv4Packet::parse_packet(rest) {
        Ok((header, remainder)) => (Some(header), remainder),
        Err(_) => (None, rest),
    };

    let udp = match &ipv4 {
        Some(header) if header.protocol == 0x11 => UdpDatagram::parse_datagram(rest).ok(),
        _ => None,
    };

    Ok(Packet {
        ethernet,
        ipv4,
        udp,
    })
}

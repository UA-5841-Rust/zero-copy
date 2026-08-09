pub mod error;
pub mod ethernet;
pub mod ipv4;
pub mod udp;

use error::ParseError;
use ethernet::EthernetHeader;
use ipv4::Ipv4Header;
use udp::UdpDatagram;

const ETHERNET_HEADER_SIZE: usize = 14;
const MIN_IPV4_HEADER_SIZE: usize = 20;
const MIN_UDP_DATAGRAM_SIZE: usize = 8;
const MIN_DATA_SIZE: usize = ETHERNET_HEADER_SIZE + MIN_IPV4_HEADER_SIZE + MIN_UDP_DATAGRAM_SIZE;

pub struct Packet<'a> {
    pub ethernet: EthernetHeader,
    pub ipv4: Ipv4Header<'a>,
    pub udp: UdpDatagram<'a>,
}

pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, ParseError> {
    if data.len() < MIN_DATA_SIZE {
        return Err(ParseError::PacketTooShort);
    }

    let (ethernet_header, packet) = EthernetHeader::new(data)?;
    let (ipv4_header, datagram) = Ipv4Header::new(packet)?;
    let udp_datagram = UdpDatagram::new(datagram)?;

    Ok(Packet {
        ethernet: ethernet_header,
        ipv4: ipv4_header,
        udp: udp_datagram,
    })
}

#[cfg(test)]
mod tests {}

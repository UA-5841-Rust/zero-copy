pub mod error;
pub mod ethernet;
pub mod ffi;
pub mod ipv4;
pub mod udp;

use error::ParseError;
use ethernet::EthernetHeader;
use ipv4::Ipv4Packet;
use udp::UdpDatagram;

const UDP_VALUE: u8 = 0x11;

pub struct Packet<'a> {
    pub ethernet: EthernetHeader<'a>,
    pub ipv4: Ipv4Packet<'a>,
    pub udp: UdpDatagram<'a>,
}

pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, ParseError> {
    let (ethernet, rest) = EthernetHeader::parse_ethernet(data)?;
    let (ipv4, rest) = Ipv4Packet::parse_packet(rest)?;

    if ipv4.protocol != UDP_VALUE {
        return Err(ParseError::UnsupportedProtocol);
    }

    let udp = UdpDatagram::parse_datagram(rest)?;

    Ok(Packet {
        ethernet,
        ipv4,
        udp,
    })
}

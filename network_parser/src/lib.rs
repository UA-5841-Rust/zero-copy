mod error;
mod ethernet;

use error::ParseError;
use ethernet::EthernetHeader;

const ETHERNET_HEADER_SIZE: usize = 14;
const MIN_IPV4_HEADER_SIZE: usize = 20;
const MIN_UDP_DATAGRAM_SIZE: usize = 8;
const MIN_DATA_SIZE: usize = ETHERNET_HEADER_SIZE + MIN_IPV4_HEADER_SIZE + MIN_UDP_DATAGRAM_SIZE;

pub struct Packet<'a> {
    pub ethernet: EthernetHeader<'a>,
    // pub ipv4: Option<Ipv4Header>,
    // pub udp: Option<UdpPacket<'a>>,
}

pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, ParseError> {
    if data.len() < MIN_DATA_SIZE {
        return Err(ParseError::PacketTooShort);
    }

    let ethernet_header = EthernetHeader::new(data)?;

    Ok(Packet {
        ethernet: ethernet_header,
    })
}

#[cfg(test)]
mod tests {}

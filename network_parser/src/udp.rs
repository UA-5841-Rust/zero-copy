use crate::error::ParseError;

const MIN_UDP_HEADER: usize = 8;
pub struct UdpDatagram<'a> {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse_datagram(datagram: &'a [u8]) -> Result<Self, ParseError> {
        if datagram.len() < MIN_UDP_HEADER {
            return Err(ParseError::PacketTooShort);
        }
        let source = u16::from_be_bytes([datagram[0], datagram[1]]);
        let destination = u16::from_be_bytes([datagram[2], datagram[3]]);
        let length = u16::from_be_bytes([datagram[4], datagram[5]]);
        let checksum = u16::from_be_bytes([datagram[6], datagram[7]]);

        if length < MIN_UDP_HEADER as u16 {
            return Err(ParseError::InvalidUdpLength);
        }
        if datagram.len() < length.into() {
            return Err(ParseError::InvalidUdpLength);
        }

        let payload_size = usize::from(length) - MIN_UDP_HEADER;
        let payload = &datagram[MIN_UDP_HEADER..MIN_UDP_HEADER + payload_size];

        Ok(UdpDatagram {
            source,
            destination,
            length,
            checksum,
            payload,
        })
    }
}

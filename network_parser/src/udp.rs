use crate::error::ParseError;

const MIN_UDP_HEADER_SIZE: usize = 8;

/// Represents a UDP datagram.
///
/// Contains the source/destination ports, length, checksum, and a
/// zero-copy reference to the UDP payload data.
#[derive(Debug, PartialEq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Parses a UDP datagram from a raw byte slice.
    ///
    /// Extracts the UDP header fields and returns a `UdpDatagram` containing
    /// a slice that points directly to the payload. Returns an error if the
    /// datagram length is invalid or truncated.
    pub fn new(datagram: &'a [u8]) -> Result<Self, ParseError> {
        let (header, rest_payload) = datagram
            .split_first_chunk::<MIN_UDP_HEADER_SIZE>()
            .ok_or(ParseError::PacketTooShort)?;

        let source_port = u16::from_be_bytes([header[0], header[1]]);
        let destination_port = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[4], header[5]]);

        let length_usize = length as usize;
        if length_usize < MIN_UDP_HEADER_SIZE {
            return Err(ParseError::InvalidUdpLength);
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);

        let payload_length = length_usize - MIN_UDP_HEADER_SIZE;
        let payload = rest_payload
            .get(..payload_length)
            .ok_or(ParseError::InvalidUdpLength)?;

        Ok(UdpDatagram {
            source_port,
            destination_port,
            length,
            checksum,
            payload,
        })
    }
}

use crate::error::ParseError;

const MIN_HEADER_SIZE: usize = 14;
const IPV4_VALUE: u16 = 0x0800;

pub struct EthernetHeader<'a> {
    pub destination: &'a [u8],
    pub source: &'a [u8],
    pub ethertype: u16,
}

impl<'a> EthernetHeader<'a> {
    pub fn parse_ethernet(frame: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if frame.len() < MIN_HEADER_SIZE {
            return Err(ParseError::PacketTooShort);
        }

        let destination = &frame[0..6];
        let source = &frame[6..12];
        let ether_bytes = [frame[12], frame[13]];
        let ethertype = u16::from_be_bytes(ether_bytes);

        if ethertype != IPV4_VALUE {
            return Err(ParseError::InvalidEtherType);
        }

        let header = EthernetHeader {
            destination,
            source,
            ethertype,
        };

        Ok((header, &frame[MIN_HEADER_SIZE..]))
    }
}

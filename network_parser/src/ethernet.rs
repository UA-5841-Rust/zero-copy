use crate::error::ParseError;

const MAC_ADDR_LEN: usize = 6;
const ETHERNET_TYPE_LEN: usize = 2;
const IPV4_ETHER_TYPE: u16 = 0x0800;
const IPV4_ETHER_TYPE_BYTES: [u8; 2] = [0x08, 0x00];

#[derive(Debug)]
pub struct EthernetHeader<'a> {
    pub destination_mac: &'a [u8; MAC_ADDR_LEN],
    pub source_mac: &'a [u8; MAC_ADDR_LEN],
    pub ether_type: u16,
}

impl<'a> EthernetHeader<'a> {
    pub fn new(frame: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (dest_mac, rest) = frame
            .split_first_chunk::<MAC_ADDR_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        let (src_mac, rest) = rest
            .split_first_chunk::<MAC_ADDR_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        let (ethertype_bytes, payload) = rest
            .split_first_chunk::<ETHERNET_TYPE_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        if ethertype_bytes != &IPV4_ETHER_TYPE_BYTES {
            return Err(ParseError::InvalidEtherType);
        }

        Ok((
            EthernetHeader {
                destination_mac: dest_mac,
                source_mac: src_mac,
                ether_type: IPV4_ETHER_TYPE,
            },
            payload,
        ))
    }
}

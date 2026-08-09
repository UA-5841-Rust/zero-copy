use crate::error::ParseError;
use std::fmt;

const MAC_ADDR_LEN: usize = 6;
const ETHERNET_TYPE_LEN: usize = 2;
const IPV4_ETHER_TYPE: u16 = 0x0800;

#[derive(PartialEq)]
pub struct EthernetHeader {
    pub destination_mac: [u8; MAC_ADDR_LEN],
    pub source_mac: [u8; MAC_ADDR_LEN],
    pub ether_type: u16,
}

impl fmt::Debug for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthernetHeader")
            .field(
                "destination_mac",
                &format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.destination_mac[0],
                    self.destination_mac[1],
                    self.destination_mac[2],
                    self.destination_mac[3],
                    self.destination_mac[4],
                    self.destination_mac[5]
                ),
            )
            .field(
                "source_mac",
                &format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.source_mac[0],
                    self.source_mac[1],
                    self.source_mac[2],
                    self.source_mac[3],
                    self.source_mac[4],
                    self.source_mac[5]
                ),
            )
            .field("ether_type", &format_args!("{:#06x}", self.ether_type))
            .finish()
    }
}

impl EthernetHeader {
    pub fn new(frame: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (dest_mac, rest) = frame
            .split_first_chunk::<MAC_ADDR_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        let (src_mac, rest) = rest
            .split_first_chunk::<MAC_ADDR_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        let (ethertype_bytes, payload) = rest
            .split_first_chunk::<ETHERNET_TYPE_LEN>()
            .ok_or(ParseError::PacketTooShort)?;

        let ether_type = u16::from_be_bytes(*ethertype_bytes);
        if ether_type != IPV4_ETHER_TYPE {
            return Err(ParseError::InvalidEtherType);
        }

        Ok((
            EthernetHeader {
                destination_mac: *dest_mac,
                source_mac: *src_mac,
                ether_type,
            },
            payload,
        ))
    }
}

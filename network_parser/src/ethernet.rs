use crate::error::ParseError;
use std::fmt;

const MAC_ADDR_LEN: usize = 6;
const ETHERNET_TYPE_LEN: usize = 2;
const IPV4_ETHER_TYPE: u16 = 0x0800;

/// Represents an Ethernet II frame header.
#[derive(Debug, PartialEq)]
pub struct EthernetHeader {
    pub destination_mac: [u8; MAC_ADDR_LEN],
    pub source_mac: [u8; MAC_ADDR_LEN],
    pub ether_type: u16,
}

impl EthernetHeader {
    /// Parses an Ethernet II header from a raw byte slice.
    ///
    /// Returns a tuple containing the parsed `EthernetHeader` and a slice pointing
    /// to the remaining payload, or a `ParseError` if the frame is invalid or too short.
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

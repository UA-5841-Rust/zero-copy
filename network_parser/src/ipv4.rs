use crate::{MIN_IPV4_HEADER_SIZE, error::ParseError};
use std::net::Ipv4Addr;

const IP_VERSION: u8 = 4;
const MIN_IHL_VALUE: u8 = 5;
const IHL_WORD: usize = 4;
const UDP_PROTOCOL: u8 = 0x11;

#[derive(Debug, PartialEq)]
pub struct Ipv4Header<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: Ipv4Addr,
    pub destination_addr: Ipv4Addr,
    pub options: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub fn new(packet: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let ([ver_ihl, dscp_ecn], rest) = packet
            .split_first_chunk::<2>()
            .ok_or(ParseError::PacketTooShort)?;

        let version = ver_ihl >> 4;
        if version != IP_VERSION {
            return Err(ParseError::InvalidIpv4Version);
        }

        let ihl = ver_ihl & 0x0F;
        if ihl < MIN_IHL_VALUE {
            return Err(ParseError::InvalidIpv4HeaderLength);
        }

        let (fixed_hdr, rest) = rest
            .split_first_chunk::<18>()
            .ok_or(ParseError::PacketTooShort)?;

        let header_len = (ihl as usize) * IHL_WORD;
        let options_len = header_len - MIN_IPV4_HEADER_SIZE;

        let (options, payload) = rest
            .split_at_checked(options_len)
            .ok_or(ParseError::InvalidIpv4HeaderLength)?;

        let total_length = u16::from_be_bytes([fixed_hdr[0], fixed_hdr[1]]);
        let total_len_usize = total_length as usize;

        if total_len_usize < header_len {
            return Err(ParseError::InvalidIpv4TotalLength);
        }

        let expected_payload_len = total_len_usize - header_len;

        let actual_payload = payload
            .get(..expected_payload_len)
            .ok_or(ParseError::InvalidIpv4TotalLength)?;

        let identification = u16::from_be_bytes([fixed_hdr[2], fixed_hdr[3]]);
        let flags_fragment_offset = u16::from_be_bytes([fixed_hdr[4], fixed_hdr[5]]);
        let ttl = fixed_hdr[6];

        let protocol = fixed_hdr[7];
        if protocol != UDP_PROTOCOL {
            return Err(ParseError::UnsupportedProtocol);
        }

        let header_checksum = u16::from_be_bytes([fixed_hdr[8], fixed_hdr[9]]);
        let source_addr = Ipv4Addr::from_octets(
            fixed_hdr[10..14]
                .try_into()
                .map_err(|_| ParseError::PacketTooShort)?,
        );
        let destination_addr = Ipv4Addr::from_octets(
            fixed_hdr[14..18]
                .try_into()
                .map_err(|_| ParseError::PacketTooShort)?,
        );

        Ok((
            Ipv4Header {
                version,
                ihl,
                dscp_ecn: *dscp_ecn,
                total_length,
                identification,
                flags_fragment_offset,
                ttl,
                protocol,
                header_checksum,
                source_addr,
                destination_addr,
                options,
            },
            actual_payload,
        ))
    }
}

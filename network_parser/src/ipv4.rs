use crate::error::ParseError;

const IHL_MASK: u8 = 0b00001111;
const ECN_MASK: u8 = 0b00000011;
const FLAGS_MASK: u8 = 0b11100000;
const FRAGM_MASK: u16 = 0b0001111111111111;

pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,

    pub source: &'a [u8],
    pub destination: &'a [u8],

    pub options: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse_packet(packet: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if packet.is_empty() {
            return Err(ParseError::InvalidIpv4HeaderLength);
        }

        let version = packet[0] >> 4;
        if version != 4 {
            return Err(ParseError::InvalidIpv4Version);
        }

        let ihl = packet[0] & IHL_MASK;

        if ihl < 5 {
            return Err(ParseError::InvalidIpv4HeaderLength);
        }

        let header_size: usize = (ihl * 4).into();
        if packet.len() < header_size {
            return Err(ParseError::PacketTooShort);
        }

        let dscp = packet[1] >> 2; //
        let ecn = packet[1] & ECN_MASK;
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);

        if (packet.len() < usize::from(total_len)) || (usize::from(total_len) < header_size) {
            return Err(ParseError::InvalidIpv4TotalLength);
        }

        let identification = u16::from_be_bytes([packet[4], packet[5]]);
        let flags = (packet[6] & FLAGS_MASK) >> 5;
        let fragment_offset = ((u16::from(packet[6]) << 8) | u16::from(packet[7])) & FRAGM_MASK;
        let ttl = packet[8];
        let protocol = packet[9];
        let checksum = u16::from_be_bytes([packet[10], packet[11]]);
        let source = &packet[12..16];
        let destination = &packet[16..20];
        let options = &packet[20..header_size];

        let payload_len = usize::from(total_len) - header_size;

        Ok((
            Ipv4Packet {
                version,
                ihl,
                dscp,
                ecn,
                total_len,
                identification,
                flags,
                fragment_offset,
                ttl,
                protocol,
                checksum,
                source,
                destination,
                options,
            },
            &packet[header_size..header_size + payload_len],
        ))
    }
}

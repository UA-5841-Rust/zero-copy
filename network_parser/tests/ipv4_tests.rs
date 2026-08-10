use network_parser::error::ParseError;
use network_parser::ipv4::Ipv4Header;
use std::net::Ipv4Addr;

const VALID_IPV4: &[u8] = &[
    0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
];

const IPV4_WITH_OPTIONS: &[u8] = &[
    0x46, 0x00, 0x00, 0x24, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55,
];

#[test]
fn test_parse_valid_ipv4() {
    let result = Ipv4Header::new(VALID_IPV4);
    assert!(result.is_ok());

    let (header, payload) = result.unwrap();

    assert_eq!(header.version, 4);
    assert_eq!(header.ihl, 5);
    assert_eq!(header.total_length, 32);
    assert_eq!(header.protocol, 0x11);
    assert_eq!(header.source_addr, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(header.destination_addr, Ipv4Addr::new(192, 168, 1, 2));
    assert!(header.options.is_empty());

    assert_eq!(payload.len(), 12);
    assert_eq!(payload[0], 0xAA);
}

#[test]
fn test_parse_ipv4_with_options() {
    let result = Ipv4Header::new(IPV4_WITH_OPTIONS);
    assert!(result.is_ok());

    let (header, _payload) = result.unwrap();

    assert_eq!(header.version, 4);
    assert_eq!(header.ihl, 6);

    assert_eq!(header.options, &[0x01, 0x01, 0x01, 0x01]);
}

#[test]
fn test_invalid_version() {
    let mut bad_packet = VALID_IPV4.to_vec();
    bad_packet[0] = 0x55; // version=5, IHL=5

    let result = Ipv4Header::new(&bad_packet);
    assert_eq!(result.unwrap_err(), ParseError::InvalidIpv4Version);
}

#[test]
fn test_invalid_ihl() {
    let mut bad_packet = VALID_IPV4.to_vec();
    bad_packet[0] = 0x44; // version=4, IHL=4

    let result = Ipv4Header::new(&bad_packet);
    assert_eq!(result.unwrap_err(), ParseError::InvalidIpv4HeaderLength);
}

#[test]
fn test_unsupported_protocol() {
    let mut bad_packet = VALID_IPV4.to_vec();
    bad_packet[9] = 0x06; // udp => tcp

    let result = Ipv4Header::new(&bad_packet);

    assert_eq!(result.unwrap_err(), ParseError::UnsupportedProtocol);
}

#[test]
fn test_invalid_total_length() {
    let mut bad_packet = VALID_IPV4.to_vec();

    // total Length = 10
    bad_packet[2] = 0x00;
    bad_packet[3] = 0x0A;

    let result = Ipv4Header::new(&bad_packet);
    assert_eq!(result.unwrap_err(), ParseError::InvalidIpv4TotalLength);
}

#[test]
fn test_packet_too_short() {
    let short_packet = &VALID_IPV4[..10];

    let result = Ipv4Header::new(short_packet);
    assert_eq!(result.unwrap_err(), ParseError::PacketTooShort);
}

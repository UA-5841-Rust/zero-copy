use network_parser::error::ParseError;
use network_parser::parse_packet;

fn valid_packet() -> Vec<u8> {
    vec![
        // Ethernet
        // destination MAC
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // source MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // etherType = IPv4
        0x08, 0x00, // IPv4
        // version = 4, IHL = 5
        0x45, // DSCP = 0, ECN = 0
        0x00, // total length = 20 + 8 + 5 = 33
        0x00, 0x21, // identification
        0x12, 0x34, // flags, fragment offset
        0x00, 0x00, // TTL
        0x40, // protocol
        0x11, // checksum
        0x00, 0x00, // source IP
        192, 168, 1, 10, // destination IP
        192, 168, 1, 20, // UDP
        // source port
        0x04, 0xD2, // destination port
        0x16, 0x2E, // UDP length = 8 + 5 = 13
        0x00, 0x0D, // checksum
        0x00, 0x00, // payload - 5
        b'h', b'e', b'l', b'l', b'o',
    ]
}

#[test]
fn parse_valid_packet() {
    let data = valid_packet();

    let packet = parse_packet(&data).unwrap();
    assert_eq!(
        packet.ethernet.destination,
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
    );
    assert_eq!(
        packet.ethernet.source,
        &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    );
    assert_eq!(packet.ethernet.ethertype, 0x0800);

    assert_eq!(packet.ipv4.version, 4);
    assert_eq!(packet.ipv4.ihl, 5);
    assert_eq!(packet.ipv4.total_len, 33);
    assert_eq!(packet.ipv4.protocol, 0x11);
    assert_eq!(packet.ipv4.source, &[192, 168, 1, 10]);
    assert_eq!(packet.ipv4.destination, &[192, 168, 1, 20]);

    assert_eq!(packet.udp.source, 1234);
    assert_eq!(packet.udp.destination, 5678);
    assert_eq!(packet.udp.length, 13);
    assert_eq!(packet.udp.payload, b"hello");
}

#[test]
fn parse_empty_udp() {
    let mut data = valid_packet();
    data[16] = 0x00;
    data[17] = 0x1C;
    data[38] = 0x00;
    data[39] = 0x08;

    data.truncate(42);
    let packet = parse_packet(&data).unwrap();
    assert_eq!(packet.ipv4.total_len, 28);
    assert_eq!(packet.udp.length, 8);
    assert!(packet.udp.payload.is_empty());
}

#[test]
fn parse_ipv4_with_opt() {
    let mut data = valid_packet();
    data[14] = 0x46;
    data[16] = 0x00;
    data[17] = 0x25;

    data.splice(34..34, [0x01, 0x02, 0x03, 0x04]);

    let packet = parse_packet(&data).unwrap();

    assert_eq!(packet.ipv4.ihl, 6);
    assert_eq!(packet.ipv4.options, &[0x01, 0x02, 0x03, 0x04]);

    assert_eq!(packet.udp.source, 1234);
    assert_eq!(packet.udp.destination, 5678);
    assert_eq!(packet.udp.payload, b"hello");
}

#[test]
fn parse_packet_too_short() {
    let data = [0u8; 10];

    match parse_packet(&data) {
        Err(ParseError::PacketTooShort) => {}
        _ => panic!("expected PacketTooShort"),
    }
}

#[test]
fn parse_invalid_ehertype() {
    let mut data = valid_packet();
    data[12] = 0x08;
    data[13] = 0x06;

    match parse_packet(&data) {
        Err(ParseError::InvalidEtherType) => {}
        _ => panic!("expected InvalidEtherType"),
    }
}

#[test]
fn parse_invalid_ipv4_ver() {
    let mut data = valid_packet();
    data[14] = 0x65;

    match parse_packet(&data) {
        Err(ParseError::InvalidIpv4Version) => {}
        _ => panic!("expected InvalidIpv4Version"),
    }
}

#[test]
fn parse_invalid_ipv4_header_len() {
    let mut data = valid_packet();
    data[14] = 0x44;

    match parse_packet(&data) {
        Err(ParseError::InvalidIpv4HeaderLength) => {}
        _ => panic!("expected InvalidIpv4HeaderLength"),
    }
}

#[test]
fn parse_invalid_ipv4_total_length_too_small() {
    let mut data = valid_packet();
    data[16] = 0x00;
    data[17] = 0x0A;

    match parse_packet(&data) {
        Err(ParseError::InvalidIpv4TotalLength) => {}
        _ => panic!("expected InvalidIpv4TotalLength"),
    }
}

#[test]
fn parse_invalid_ipv4_total_length_too_large() {
    let mut data = valid_packet();
    data[16] = 0x00;
    data[17] = 0x64;

    match parse_packet(&data) {
        Err(ParseError::InvalidIpv4TotalLength) => {}
        _ => panic!("expected InvalidIpv4TotalLength"),
    }
}

#[test]
fn parse_invalid_udp_length_too_small() {
    let mut data = valid_packet();
    data[38] = 0x00;
    data[39] = 0x07;

    match parse_packet(&data) {
        Err(ParseError::InvalidUdpLength) => {}
        _ => panic!("expected InvalidUdpLength"),
    }
}

#[test]
fn parse_invalid_udp_length_too_large() {
    let mut data = valid_packet();
    data[38] = 0x00;
    data[39] = 0x64;

    match parse_packet(&data) {
        Err(ParseError::InvalidUdpLength) => {}
        _ => panic!("expected InvalidUdpLength"),
    }
}

#[test]
fn parse_truncated_udp_payload() {
    let mut data = valid_packet();
    data[38] = 0x00;
    data[39] = 0x12;

    // Actual payload is only 5 bytes.
    data.truncate(47);

    match parse_packet(&data) {
        Err(ParseError::InvalidUdpLength) => {}
        _ => panic!("expected InvalidUdpLength"),
    }
}

#[test]
fn parse_unsupported_protocol() {
    let mut data = valid_packet();
    data[23] = 0x06;

    match parse_packet(&data) {
        Err(ParseError::UnsupportedProtocol) => {}
        _ => panic!("expected UnsupportedProtocol"),
    }
}

#[test]
fn udp_payload_is_zero_copy() {
    let data = valid_packet();
    let packet = parse_packet(&data).unwrap();
    let payload = packet.udp.payload;
    let expected_start = 42;

    assert_eq!(payload, b"hello");
    assert_eq!(payload.as_ptr(), data[expected_start..].as_ptr());
}

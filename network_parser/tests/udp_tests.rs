use network_parser::error::ParseError;
use network_parser::udp::UdpDatagram;

const VALID_UDP: &[u8] = &[
    0x30, 0x39, 0x15, 0xb3, 0x00, 0x0d, 0x00, 0x00, b'H', b'e', b'l', b'l', b'o',
];

const EMPTY_PAYLOAD_UDP: &[u8] = &[0x30, 0x39, 0x15, 0xb3, 0x00, 0x08, 0x12, 0x34];

#[test]
fn test_parse_valid_udp() {
    let result = UdpDatagram::new(VALID_UDP);
    assert!(result.is_ok());

    let datagram = result.unwrap();

    assert_eq!(datagram.source_port, 12345);
    assert_eq!(datagram.destination_port, 5555);
    assert_eq!(datagram.length, 13);
    assert_eq!(datagram.checksum, 0x0000);
    assert_eq!(datagram.payload, b"Hello");
}

#[test]
fn test_parse_empty_payload_udp() {
    let result = UdpDatagram::new(EMPTY_PAYLOAD_UDP);
    assert!(result.is_ok());

    let datagram = result.unwrap();

    assert_eq!(datagram.length, 8);
    assert!(datagram.payload.is_empty());
}

#[test]
fn test_invalid_udp_length_less_than_header() {
    let mut bad_udp = VALID_UDP.to_vec();

    // len = 7 (min is 8)
    bad_udp[4] = 0x00;
    bad_udp[5] = 0x07;

    let result = UdpDatagram::new(&bad_udp);
    assert_eq!(result.unwrap_err(), ParseError::InvalidUdpLength);
}

#[test]
fn test_truncated_udp_payload() {
    let mut bad_udp = VALID_UDP.to_vec();

    // len 20 while real 13
    bad_udp[4] = 0x00;
    bad_udp[5] = 0x14;

    let result = UdpDatagram::new(&bad_udp);
    assert_eq!(result.unwrap_err(), ParseError::InvalidUdpLength);
}

#[test]
fn test_udp_header_too_short() {
    let short_udp = &VALID_UDP[..5];

    let result = UdpDatagram::new(short_udp);
    assert_eq!(result.unwrap_err(), ParseError::PacketTooShort);
}

#[test]
fn test_udp_zero_copy() {
    let datagram = UdpDatagram::new(VALID_UDP).unwrap();

    let original_buf_ptr = VALID_UDP.as_ptr() as usize;
    let payload_ptr = datagram.payload.as_ptr() as usize;

    assert_eq!(
        payload_ptr,
        original_buf_ptr + 8,
        "UDP Payload reference is not zero-copy!"
    );
}

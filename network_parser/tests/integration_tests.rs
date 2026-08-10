use network_parser::{error::ParseError, parse_packet};
use std::net::Ipv4Addr;

const FULL_VALID_PACKET: &[u8] = &[
    0x7c, 0xf1, 0x7e, 0x36, 0xb1, 0xca, 0x80, 0x91, 0x33, 0x71, 0xee, 0x33, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x21, 0xf0, 0x2f, 0x00, 0x00, 0x80, 0x11, 0xc7, 0xdd, 0xc0, 0xa8, 0x00, 0x67, 0xc0, 0xa8,
    0x01, 0x01, 0xe4, 0x29, 0x15, 0xb3, 0x00, 0x0d, 0x78, 0x56, b'H', b'e', b'l', b'l', b'o',
];

#[test]
fn test_parse_full_pipeline() {
    let result = parse_packet(FULL_VALID_PACKET);
    assert!(result.is_ok());

    let packet = result.unwrap();

    assert_eq!(packet.ethernet.ether_type, 0x0800);

    assert_eq!(packet.ipv4.version, 4);
    assert_eq!(packet.ipv4.source_addr, Ipv4Addr::new(192, 168, 0, 103));

    assert_eq!(packet.udp.destination_port, 5555);
    assert_eq!(packet.udp.payload, b"Hello");
}

#[test]
fn test_integration_zero_copy_proof() {
    let packet = parse_packet(FULL_VALID_PACKET).expect("Valid packet parsing failed");

    let original_buf_ptr = FULL_VALID_PACKET.as_ptr() as usize;
    let payload_ptr = packet.udp.payload.as_ptr() as usize;

    let expected_offset = 42;

    assert_eq!(
        payload_ptr,
        original_buf_ptr + expected_offset,
        "Zero-copy proof failed! Payload does not point to the original buffer at the correct offset."
    );
}

#[test]
fn test_global_packet_too_short() {
    let short_packet = &FULL_VALID_PACKET[..41];

    let result = parse_packet(short_packet);
    assert_eq!(result.unwrap_err(), ParseError::PacketTooShort);
}

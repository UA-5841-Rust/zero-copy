use network_parser::error::ParseError;
use network_parser::ethernet::EthernetHeader;

const VALID_FRAME: &[u8] = &[
    0x7c, 0xf1, 0x7e, 0x36, 0xb1, 0xca, 0x80, 0x91, 0x33, 0x71, 0xee, 0x33, 0x8, 0x0, 0x45, 0x0,
    0x0, 0x27, 0xf0, 0x2f, 0x0, 0x0, 0x80, 0x11, 0xc7, 0xdd, 0xc0, 0xa8, 0x0, 0x67, 0xc0, 0xa8,
    0x1, 0x1, 0xe4, 0x29, 0x15, 0xb3, 0x0, 0x13, 0x78, 0x56, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
    0x52, 0x75, 0x73, 0x74, 0x21,
];

#[test]
fn test_parse_valid_packet() {
    let result = EthernetHeader::new(VALID_FRAME);
    assert!(result.is_ok());

    let (header, payload) = result.unwrap();

    assert_eq!(header.destination_mac, [0x7c, 0xf1, 0x7e, 0x36, 0xb1, 0xca]);
    assert_eq!(header.source_mac, [0x80, 0x91, 0x33, 0x71, 0xee, 0x33]);
    assert_eq!(header.ether_type, 0x0800);

    assert_eq!(payload, &VALID_FRAME[14..]);
}

#[test]
fn test_packet_too_short() {
    let short_frame = &VALID_FRAME[..13];

    let result = EthernetHeader::new(short_frame);

    assert_eq!(result.unwrap_err(), ParseError::PacketTooShort);
}

#[test]
fn test_invalid_ethertype() {
    let mut invalid_frame = VALID_FRAME.to_vec();
    
    // ipv4 -> arp
    invalid_frame[12] = 0x08;
    invalid_frame[13] = 0x06;

    let result = EthernetHeader::new(&invalid_frame);

    assert_eq!(result.unwrap_err(), ParseError::InvalidEtherType);
}

#[test]
fn test_zero_copy_behavior() {
    let (_header, payload) = EthernetHeader::new(VALID_FRAME).unwrap();

    let frame_ptr = VALID_FRAME.as_ptr() as usize;
    let payload_ptr = payload.as_ptr() as usize;

    assert_eq!(
        payload_ptr,
        frame_ptr + 14,
        "Payload memory pointer does not match the expected zero-copy offset."
    );
}

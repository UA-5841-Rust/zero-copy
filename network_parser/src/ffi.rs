use std::os::raw::c_uchar;

#[repr(C)]
pub struct CEthernetHeader {
    pub destination_mac: [c_uchar; 6],
    pub source_mac: [c_uchar; 6],
    pub ether_type: u16,
}

#[repr(C)]
pub struct CIpv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: [u8; 4],
    pub destination_addr: [u8; 4],

    pub options: *const u8,
    pub options_len: usize,
}

#[repr(C)]
pub struct CUdpPacket {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: *const c_uchar,
    pub payload_len: usize,
}

#[repr(C)]
pub struct PacketHandle {
    pub ethernet: CEthernetHeader,
    pub ipv4: CIpv4Header,
    pub udp: CUdpPacket,
}

/// Parses a raw network packet from a byte buffer into a C-compatible packet structure.
///
/// # Safety
///
/// - `data` must be a valid, readable pointer to at least `len` bytes, or `NULL`.
/// - The memory region pointed to by `data` must remain valid and unmodified for the entire
///   lifetime of the returned `PacketHandle`.
/// - `len` must accurately reflect the size of the buffer at `data`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_parse(data: *const u8, len: usize) -> *mut PacketHandle {
    if data.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let slice = unsafe { std::slice::from_raw_parts(data, len) };

    match crate::parse_packet(slice) {
        Ok(parsed_packet) => {
            let handle = PacketHandle {
                ethernet: CEthernetHeader {
                    destination_mac: parsed_packet.ethernet.destination_mac,
                    source_mac: parsed_packet.ethernet.source_mac,
                    ether_type: parsed_packet.ethernet.ether_type,
                },

                ipv4: CIpv4Header {
                    version: parsed_packet.ipv4.version,
                    ihl: parsed_packet.ipv4.ihl,
                    dscp_ecn: parsed_packet.ipv4.dscp_ecn,
                    total_length: parsed_packet.ipv4.total_length,
                    identification: parsed_packet.ipv4.identification,
                    flags_fragment_offset: parsed_packet.ipv4.flags_fragment_offset,
                    ttl: parsed_packet.ipv4.ttl,
                    protocol: parsed_packet.ipv4.protocol,
                    header_checksum: parsed_packet.ipv4.header_checksum,
                    source_addr: parsed_packet.ipv4.source_addr.octets(),
                    destination_addr: parsed_packet.ipv4.destination_addr.octets(),

                    options: if parsed_packet.ipv4.options.is_empty() {
                        std::ptr::null()
                    } else {
                        parsed_packet.ipv4.options.as_ptr()
                    },
                    options_len: parsed_packet.ipv4.options.len(),
                },

                udp: CUdpPacket {
                    source_port: parsed_packet.udp.source_port,
                    destination_port: parsed_packet.udp.destination_port,
                    length: parsed_packet.udp.length,
                    checksum: parsed_packet.udp.checksum,

                    payload: if parsed_packet.udp.payload.is_empty() {
                        std::ptr::null()
                    } else {
                        parsed_packet.udp.payload.as_ptr()
                    },
                    payload_len: parsed_packet.udp.payload.len(),
                },
            };

            let boxed_handle = Box::new(handle);
            Box::into_raw(boxed_handle)
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees the memory allocated for a `PacketHandle`.
///
/// # Safety
///
/// - `handle` must be a pointer previously allocated by `packet_parse`, or `NULL`.
/// - `handle` must not have been previously freed (avoids double-free).
/// - The pointer must not be dereferenced after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_free(handle: *mut PacketHandle) {
    if !handle.is_null() {
        let _boxed = unsafe { Box::from_raw(handle) };
    }
}

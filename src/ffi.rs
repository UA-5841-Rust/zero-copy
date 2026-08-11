//! C-compatible bindings for the zero-copy parser.
//!
//! The input buffer remains owned by the C/C++ caller. A successful
//! [`packet_parse`] result borrows its payload from that buffer, so the caller
//! must keep the buffer valid and unchanged until [`packet_free`] is called.

use crate::{parse_packet, Packet, ParseError};

/// Successful FFI operation.
pub const PACKET_STATUS_OK: i32 = 0;
/// A required FFI pointer was null.
pub const PACKET_STATUS_NULL_POINTER: i32 = 1;
/// The buffer ended before a required packet field.
pub const PACKET_STATUS_PACKET_TOO_SHORT: i32 = 2;
/// The Ethernet EtherType was not IPv4.
pub const PACKET_STATUS_INVALID_ETHERTYPE: i32 = 3;
/// The IPv4 version was not four.
pub const PACKET_STATUS_INVALID_IPV4_VERSION: i32 = 4;
/// The IPv4 IHL was invalid.
pub const PACKET_STATUS_INVALID_IPV4_HEADER_LENGTH: i32 = 5;
/// The IPv4 total length was invalid.
pub const PACKET_STATUS_INVALID_IPV4_TOTAL_LENGTH: i32 = 6;
/// The UDP length was invalid.
pub const PACKET_STATUS_INVALID_UDP_LENGTH: i32 = 7;
/// The IPv4 protocol was not UDP.
pub const PACKET_STATUS_UNSUPPORTED_PROTOCOL: i32 = 8;
/// The packet had another malformed structure.
pub const PACKET_STATUS_MALFORMED_PACKET: i32 = 9;
/// An FFI getter received an invalid pointer argument.
pub const PACKET_STATUS_INVALID_ARGUMENT: i32 = -1;

/// An opaque handle allocated by Rust and returned to C/C++.
///
/// It owns only the handle allocation, not the input buffer or payload.
#[repr(C)]
pub struct PacketHandle {
    source_port: u16,
    destination_port: u16,
    payload_ptr: *const u8,
    payload_len: usize,
    ethertype: u16,
    ipv4_protocol: u8,
}

impl<'a> From<Packet<'a>> for PacketHandle {
    fn from(packet: Packet<'a>) -> Self {
        Self {
            source_port: packet.udp.source_port,
            destination_port: packet.udp.destination_port,
            payload_ptr: packet.udp.payload.as_ptr(),
            payload_len: packet.udp.payload.len(),
            ethertype: packet.ethernet.ethertype,
            ipv4_protocol: packet.ipv4.protocol,
        }
    }
}

fn status_for_error(error: ParseError) -> i32 {
    match error {
        ParseError::PacketTooShort => PACKET_STATUS_PACKET_TOO_SHORT,
        ParseError::InvalidEtherType => PACKET_STATUS_INVALID_ETHERTYPE,
        ParseError::InvalidIpv4Version => PACKET_STATUS_INVALID_IPV4_VERSION,
        ParseError::InvalidIpv4HeaderLength => PACKET_STATUS_INVALID_IPV4_HEADER_LENGTH,
        ParseError::InvalidIpv4TotalLength => PACKET_STATUS_INVALID_IPV4_TOTAL_LENGTH,
        ParseError::InvalidUdpLength => PACKET_STATUS_INVALID_UDP_LENGTH,
        ParseError::UnsupportedProtocol => PACKET_STATUS_UNSUPPORTED_PROTOCOL,
        ParseError::MalformedPacket => PACKET_STATUS_MALFORMED_PACKET,
    }
}

unsafe fn parse_handle(data: *const u8, len: usize) -> Result<PacketHandle, i32> {
    if data.is_null() {
        return Err(PACKET_STATUS_NULL_POINTER);
    }

    // SAFETY: `packet_parse` and `packet_parse_with_status` require `data` to
    // point to `len` readable bytes for the duration of this call.
    let packet_data = unsafe { std::slice::from_raw_parts(data, len) };
    parse_packet(packet_data)
        .map(PacketHandle::from)
        .map_err(status_for_error)
}

/// Parses a packet and returns an opaque handle, or null on failure.
///
/// For an error code, use [`packet_parse_with_status`] instead.
///
/// # Safety
/// `data` must be non-null and point to at least `len` readable bytes. The
/// caller retains ownership of that buffer and must keep it valid and
/// unchanged until the returned handle, if any, is passed to [`packet_free`].
#[no_mangle]
pub unsafe extern "C" fn packet_parse(data: *const u8, len: usize) -> *mut PacketHandle {
    // SAFETY: upheld by this function's safety contract.
    match unsafe { parse_handle(data, len) } {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Parses a packet and returns both a handle and a C-compatible status code.
///
/// On success the function returns a non-null handle and stores
/// [`PACKET_STATUS_OK`] in `out_status`. On failure it returns null and stores
/// a `PACKET_STATUS_*` error value.
///
/// # Safety
/// `data` must be non-null and point to at least `len` readable bytes.
/// `out_status` must be non-null and writable. The caller owns `data` and must
/// keep it valid and unchanged until any returned handle is freed with
/// [`packet_free`].
#[no_mangle]
pub unsafe extern "C" fn packet_parse_with_status(
    data: *const u8,
    len: usize,
    out_status: *mut i32,
) -> *mut PacketHandle {
    if out_status.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: `out_status` was checked for null; its validity and writability
    // are guaranteed by this function's safety contract.
    let status = unsafe { &mut *out_status };
    // SAFETY: upheld by this function's safety contract.
    match unsafe { parse_handle(data, len) } {
        Ok(handle) => {
            *status = PACKET_STATUS_OK;
            Box::into_raw(Box::new(handle))
        }
        Err(error_status) => {
            *status = error_status;
            std::ptr::null_mut()
        }
    }
}

/// Frees a handle returned by [`packet_parse`] or [`packet_parse_with_status`].
///
/// Passing null is allowed and has no effect.
///
/// # Safety
/// If non-null, `handle` must be a live handle returned by this library and
/// must not have been freed previously. This function does not free the input
/// packet buffer.
#[no_mangle]
pub unsafe extern "C" fn packet_free(handle: *mut PacketHandle) {
    if !handle.is_null() {
        // SAFETY: upheld by this function's safety contract.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Retrieves the zero-copy UDP payload pointer and length.
///
/// Returns [`PACKET_STATUS_OK`] on success or
/// [`PACKET_STATUS_INVALID_ARGUMENT`] for a null argument.
///
/// # Safety
/// `handle` must be a live handle returned by this library. `out_ptr` and
/// `out_len` must be valid writable pointers. The input buffer passed to the
/// parser must remain valid until `packet_free` is called.
#[no_mangle]
pub unsafe extern "C" fn packet_get_payload(
    handle: *const PacketHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return PACKET_STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the safety contract guarantees that all three pointers are valid.
    let handle = unsafe { &*handle };
    // SAFETY: the safety contract guarantees these output pointers are writable.
    unsafe {
        *out_ptr = handle.payload_ptr;
        *out_len = handle.payload_len;
    }
    PACKET_STATUS_OK
}

/// Retrieves the source UDP port through `out_port`.
///
/// # Safety
/// `handle` must be a live handle returned by this library and `out_port` must
/// be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn packet_get_source_port(
    handle: *const PacketHandle,
    out_port: *mut u16,
) -> i32 {
    if handle.is_null() || out_port.is_null() {
        return PACKET_STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the safety contract guarantees both pointers are valid.
    unsafe { *out_port = (*handle).source_port };
    PACKET_STATUS_OK
}

/// Retrieves the destination UDP port through `out_port`.
///
/// # Safety
/// `handle` must be a live handle returned by this library and `out_port` must
/// be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn packet_get_destination_port(
    handle: *const PacketHandle,
    out_port: *mut u16,
) -> i32 {
    if handle.is_null() || out_port.is_null() {
        return PACKET_STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the safety contract guarantees both pointers are valid.
    unsafe { *out_port = (*handle).destination_port };
    PACKET_STATUS_OK
}

/// Retrieves the Ethernet EtherType through `out_ethertype`.
///
/// # Safety
/// `handle` must be a live handle returned by this library and `out_ethertype`
/// must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn packet_get_ethertype(
    handle: *const PacketHandle,
    out_ethertype: *mut u16,
) -> i32 {
    if handle.is_null() || out_ethertype.is_null() {
        return PACKET_STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the safety contract guarantees both pointers are valid.
    unsafe { *out_ethertype = (*handle).ethertype };
    PACKET_STATUS_OK
}

/// Retrieves the IPv4 protocol number through `out_protocol`.
///
/// # Safety
/// `handle` must be a live handle returned by this library and `out_protocol`
/// must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn packet_get_ipv4_protocol(
    handle: *const PacketHandle,
    out_protocol: *mut u8,
) -> i32 {
    if handle.is_null() || out_protocol.is_null() {
        return PACKET_STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the safety contract guarantees both pointers are valid.
    unsafe { *out_protocol = (*handle).ipv4_protocol };
    PACKET_STATUS_OK
}

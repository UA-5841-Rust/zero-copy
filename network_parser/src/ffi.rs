use crate::{ParseError, parse_packet};
use std::ptr;

/// Error codes returned to C callers.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CParseError {
    Ok = 0,
    NullPointer = 1,
    PacketTooShort = 2,
    InvalidEtherType = 3,
    InvalidIpv4Version = 4,
    InvalidIpv4HeaderLength = 5,
    InvalidIpv4TotalLength = 6,
    InvalidUdpLength = 7,
    UnsupportedProtocol = 8,
}

impl From<ParseError> for CParseError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::PacketTooShort => CParseError::PacketTooShort,
            ParseError::InvalidEtherType => CParseError::InvalidEtherType,
            ParseError::InvalidIpv4Version => CParseError::InvalidIpv4Version,
            ParseError::InvalidIpv4HeaderLength => CParseError::InvalidIpv4HeaderLength,
            ParseError::InvalidIpv4TotalLength => CParseError::InvalidIpv4TotalLength,
            ParseError::InvalidUdpLength => CParseError::InvalidUdpLength,
            ParseError::UnsupportedProtocol => CParseError::UnsupportedProtocol,
        }
    }
}

/// Opaque handle. C sees only `*mut PacketHandle`.
pub struct PacketHandle {
    buffer: Box<[u8]>,
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    src_addr: [u8; 4],
    dest_addr: [u8; 4],
    ttl: u8,
    protocol: u8,
    src_port: u16,
    dest_port: u16,
    payload_offset: usize,
    payload_len: usize,
}

/// Parse a raw packet from C.
/// Returns null on failure. If `out_error` is non-null, writes the error code.
///
/// # Safety
/// `data` must point to at least `len` valid bytes; `out_error` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_parse(
    data: *const u8,
    len: usize,
    out_error: *mut CParseError,
) -> *mut PacketHandle {
    let set_err = |e: CParseError| {
        if !out_error.is_null() {
            unsafe { *out_error = e };
        }
    };

    if data.is_null() {
        set_err(CParseError::NullPointer);
        return ptr::null_mut();
    }

    let input = unsafe { std::slice::from_raw_parts(data, len) };
    let packet = match parse_packet(input) {
        Ok(p) => p,
        Err(e) => {
            set_err(e.into());
            return ptr::null_mut();
        }
    };

    let offset = packet.udp.payload.as_ptr() as usize - input.as_ptr() as usize;
    let handle = Box::new(PacketHandle {
        buffer: input.to_vec().into_boxed_slice(),
        dest_mac: packet.ethernet.dest_mac,
        src_mac: packet.ethernet.src_mac,
        src_addr: packet.ipv4.src_addr,
        dest_addr: packet.ipv4.dest_addr,
        ttl: packet.ipv4.ttl,
        protocol: packet.ipv4.protocol,
        src_port: packet.udp.src_port,
        dest_port: packet.udp.dest_port,
        payload_offset: offset,
        payload_len: packet.udp.payload.len(),
    });

    set_err(CParseError::Ok);
    Box::into_raw(handle)
}

/// Free a handle returned by `packet_parse`.
///
/// # Safety
/// `handle` must be null or a live pointer from `packet_parse`; double-free is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_free(handle: *mut PacketHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

// getters

/// # Safety
/// `handle` must be null or live; `out` must point to 6 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_dest_mac(handle: *const PacketHandle, out: *mut u8) -> bool {
    unsafe { copy_out(handle, out, |h| &h.dest_mac) }
}

/// # Safety
/// `handle` must be null or live; `out` must point to 6 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_src_mac(handle: *const PacketHandle, out: *mut u8) -> bool {
    unsafe { copy_out(handle, out, |h| &h.src_mac) }
}

/// # Safety
/// `handle` must be null or live; `out` must point to 4 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_src_addr(handle: *const PacketHandle, out: *mut u8) -> bool {
    unsafe { copy_out(handle, out, |h| &h.src_addr) }
}

/// # Safety
/// `handle` must be null or live; `out` must point to 4 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_dest_addr(handle: *const PacketHandle, out: *mut u8) -> bool {
    unsafe { copy_out(handle, out, |h| &h.dest_addr) }
}

/// # Safety
/// `handle` must be null or a live pointer from `packet_parse`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_ttl(handle: *const PacketHandle) -> u8 {
    unsafe { handle.as_ref() }.map_or(0, |h| h.ttl)
}

/// # Safety
/// `handle` must be null or a live pointer from `packet_parse`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_protocol(handle: *const PacketHandle) -> u8 {
    unsafe { handle.as_ref() }.map_or(0, |h| h.protocol)
}

/// # Safety
/// `handle` must be null or a live pointer from `packet_parse`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_src_port(handle: *const PacketHandle) -> u16 {
    unsafe { handle.as_ref() }.map_or(0, |h| h.src_port)
}

/// # Safety
/// `handle` must be null or a live pointer from `packet_parse`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_dest_port(handle: *const PacketHandle) -> u16 {
    unsafe { handle.as_ref() }.map_or(0, |h| h.dest_port)
}

/// Returns payload pointer and writes its length to `out_len`.
/// Pointer is valid only until `packet_free` is called.
///
/// # Safety
/// `handle` must be null or live; `out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_payload(
    handle: *const PacketHandle,
    out_len: *mut usize,
) -> *const u8 {
    if out_len.is_null() {
        return ptr::null();
    }
    let Some(h) = (unsafe { handle.as_ref() }) else {
        unsafe { *out_len = 0 };
        return ptr::null();
    };
    unsafe { *out_len = h.payload_len };
    h.buffer[h.payload_offset..h.payload_offset + h.payload_len].as_ptr()
}

/// Copy `[u8; N]` into a C buffer.
///
/// # Safety
/// `handle` must be null or live; `out` must point to `N` writable bytes.
unsafe fn copy_out<const N: usize>(
    handle: *const PacketHandle,
    out: *mut u8,
    get: impl FnOnce(&PacketHandle) -> &[u8; N],
) -> bool {
    if out.is_null() {
        return false;
    }
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return false;
    };
    unsafe { ptr::copy_nonoverlapping(get(h).as_ptr(), out, N) };
    true
}

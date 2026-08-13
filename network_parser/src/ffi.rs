use crate::error::ParseError;
use crate::parse_packet;
use std::panic;
use std::ptr;
use std::slice;

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
    InternalPanic = 9,
}

impl From<ParseError> for CParseError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::PacketTooShort => Self::PacketTooShort,
            ParseError::InvalidEtherType => Self::InvalidEtherType,
            ParseError::InvalidIpv4Version => Self::InvalidIpv4Version,
            ParseError::InvalidIpv4HeaderLength => Self::InvalidIpv4HeaderLength,
            ParseError::InvalidIpv4TotalLength => Self::InvalidIpv4TotalLength,
            ParseError::InvalidUdpLength => Self::InvalidUdpLength,
            ParseError::UnsupportedProtocol => Self::UnsupportedProtocol,
        }
    }
}

#[repr(C)]
pub struct CEthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
}

#[repr(C)]
pub struct CIpv4Header {
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
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub options: *const u8,
    pub options_len: usize,
}

#[repr(C)]
pub struct CUdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: *const u8,
    pub payload_len: usize,
}

//PacketHandle does not own the input buffer. The caller must keep the input buffer alive until packet_free().
#[repr(C)]
pub struct PacketHandle {
    pub ethernet: CEthernetHeader,
    pub ipv4: CIpv4Header,
    pub udp: CUdpPacket,
}

/// Parses an Ethernet/IPv4/UDP packet.
///
/// The input buffer is not copied. The returned `PacketHandle`
/// contains pointers into the original input buffer.
///
/// The caller owns the input buffer and must keep it alive
/// until `packet_free` is called.
///
/// # Safety
///
/// `data` must be either null or point to a valid readable
/// memory region containing at least `len` bytes.
///
/// If `out_error` is not null, it must point to valid writable
/// memory for a `CParseError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_parse(
    data: *const u8,
    len: usize,
    out_error: *mut CParseError,
) -> *mut PacketHandle {
    let write_err = |e: CParseError| {
        if !out_error.is_null() {
            unsafe { *out_error = e };
        }
    };

    if data.is_null() {
        write_err(CParseError::NullPointer);
        return ptr::null_mut();
    }

    let slice = unsafe { slice::from_raw_parts(data, len) };

    let result = panic::catch_unwind(|| parse_packet(slice));

    let parsed = match result {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            write_err(e.into());
            return ptr::null_mut();
        }
        Err(_) => {
            write_err(CParseError::InternalPanic);
            return ptr::null_mut();
        }
    };

    let handle = PacketHandle {
        ethernet: CEthernetHeader {
            destination: parsed.ethernet.destination.try_into().unwrap_or([0; 6]),
            source: parsed.ethernet.source.try_into().unwrap_or([0; 6]),
            ethertype: parsed.ethernet.ethertype,
        },
        ipv4: CIpv4Header {
            version: parsed.ipv4.version,
            ihl: parsed.ipv4.ihl,
            dscp: parsed.ipv4.dscp,
            ecn: parsed.ipv4.ecn,
            total_len: parsed.ipv4.total_len,
            identification: parsed.ipv4.identification,
            flags: parsed.ipv4.flags,
            fragment_offset: parsed.ipv4.fragment_offset,
            ttl: parsed.ipv4.ttl,
            protocol: parsed.ipv4.protocol,
            checksum: parsed.ipv4.checksum,
            source: parsed.ipv4.source.try_into().unwrap_or([0; 4]),
            destination: parsed.ipv4.destination.try_into().unwrap_or([0; 4]),
            options: if parsed.ipv4.options.is_empty() {
                ptr::null()
            } else {
                parsed.ipv4.options.as_ptr()
            },
            options_len: parsed.ipv4.options.len(),
        },
        udp: CUdpPacket {
            source: parsed.udp.source,
            destination: parsed.udp.destination,
            length: parsed.udp.length,
            checksum: parsed.udp.checksum,
            payload: if parsed.udp.payload.is_empty() {
                ptr::null()
            } else {
                parsed.udp.payload.as_ptr()
            },
            payload_len: parsed.udp.payload.len(),
        },
    };

    write_err(CParseError::Ok);
    Box::into_raw(Box::new(handle))
}

/// Frees a `PacketHandle` returned by `packet_parse`.
///
/// The input buffer is not freed because it is owned by the caller.
///
/// # Safety
///
/// `handle` must be either null or a valid pointer returned by
/// `packet_parse` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_free(handle: *mut PacketHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

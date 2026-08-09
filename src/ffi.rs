use std::ptr;
use std::slice;

use crate::{Packet, parse_packet};

#[allow(dead_code)]
pub struct PacketHandle<'a>(Packet<'a>);

/// # Safety
/// The caller must ensure that `data` is a valid pointer to a memory block
/// of at least `len` bytes, and that this memory is not mutated while the
/// returned `PacketHandle` is in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_parse(data: *const u8, len: usize) -> *mut PacketHandle<'static> {
    if data.is_null() || len == 0 {
        return ptr::null_mut();
    }

    let slice = unsafe { slice::from_raw_parts(data, len) };

    match parse_packet(slice) {
        Ok(packet) => {
            let handle = Box::new(PacketHandle(packet));

            Box::into_raw(handle)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// # Safety
/// The `ptr` must be a valid pointer returned by `packet_parse`, or NULL.
/// It must not be freed more than once (no double-free).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn packet_free(ptr: *mut PacketHandle<'static>) {
    if !ptr.is_null() {
        let _ = unsafe { Box::from_raw(ptr) };
    }
}

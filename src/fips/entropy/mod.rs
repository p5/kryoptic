// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Entropy callbacks and source selection for the FIPS provider.

use std::ffi::{c_int, c_uchar, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::slice;

use ossl::bindings::*;

use crate::misc::{bytes_to_slice, bytes_to_slice_mut};

mod kernel;

#[derive(Clone, Copy, Debug)]
enum EntropyError {
    Source,
}

fn fill_entropy(out: &mut [u8]) -> Result<(), EntropyError> {
    match catch_unwind(AssertUnwindSafe(|| kernel::fill(out))) {
        Ok(result) => result,
        Err(_) => Err(EntropyError::Source),
    }
}

fn mix_nonce(output: &mut [u8], salt: &[u8]) {
    for (out, salt_byte) in output.iter_mut().zip(salt) {
        *out ^= *salt_byte;
    }
}

fn entropy_len(
    entropy_bits: c_int,
    min_len: usize,
    max_len: usize,
) -> Option<usize> {
    if entropy_bits < 0 || min_len > max_len {
        return None;
    }
    let bits = usize::try_from(entropy_bits).ok()?;
    let entropy_bytes = bits.checked_add(7)? / 8;
    let len = min_len.max(entropy_bytes);
    (len > 0 && len <= max_len && len <= isize::MAX as usize).then_some(len)
}

unsafe fn allocate_and_fill(
    pout: *mut *mut c_uchar,
    len: usize,
) -> Result<usize, ()> {
    if pout.is_null() || len == 0 {
        return Err(());
    }

    // SAFETY: OpenSSL supplies a valid output pointer for this callback.
    unsafe { *pout = null_mut() };

    // SAFETY: The FIPS provider allocator returns a buffer of `len` bytes.
    let out = unsafe { super::provider::fips_malloc(len, null(), 0) };
    if out.is_null() {
        return Err(());
    }

    // SAFETY: `fips_malloc` returned a writable allocation of `len` bytes.
    let buffer = unsafe { slice::from_raw_parts_mut(out.cast::<u8>(), len) };
    if fill_entropy(buffer).is_err() {
        // SAFETY: The allocation is still owned by this callback.
        unsafe { super::provider::fips_clear_free(out, len, null(), 0) };
        crate::fips::set_entropy_error_state();
        return Err(());
    }

    // SAFETY: OpenSSL supplied `pout`, and ownership transfers to OpenSSL.
    unsafe { *pout = out.cast::<c_uchar>() };
    Ok(len)
}

pub(super) unsafe extern "C" fn fips_get_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    if pout.is_null() {
        return 0;
    }
    // SAFETY: OpenSSL supplies a valid output pointer for this callback.
    unsafe { *pout = null_mut() };

    let Some(len) = entropy_len(entropy, min_len, max_len) else {
        return 0;
    };

    // SAFETY: The callback arguments follow the OpenSSL provider ABI.
    unsafe { allocate_and_fill(pout, len) }.unwrap_or(0)
}

pub(super) unsafe extern "C" fn fips_get_nonce(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const c_void,
    salt_len: usize,
) -> usize {
    if pout.is_null() {
        return 0;
    }
    // SAFETY: OpenSSL supplies a valid output pointer for this callback.
    unsafe { *pout = null_mut() };

    if min_len == 0 || min_len > max_len || min_len > isize::MAX as usize {
        return 0;
    }
    if salt.is_null() && salt_len > 0 {
        return 0;
    }

    // SAFETY: OpenSSL supplies a valid output pointer for this callback.
    let Ok(len) = (unsafe { allocate_and_fill(pout, min_len) }) else {
        return 0;
    };

    if !salt.is_null() && salt_len > 0 {
        let mix_len = len.min(salt_len);
        // SAFETY: OpenSSL supplies `len` output bytes and `salt_len` input bytes.
        // SAFETY: The allocation is owned here until the callback returns.
        let output = unsafe { bytes_to_slice_mut(*pout, mix_len) };
        if let Ok(output) = output {
            // OpenSSL supplies `salt_len` readable input bytes.
            let input = bytes_to_slice(salt.cast::<u8>(), mix_len);
            mix_nonce(output, input);
        } else {
            // SAFETY: The allocation is still owned by this callback.
            unsafe {
                super::provider::fips_clear_free(
                    (*pout).cast::<c_void>(),
                    len,
                    null(),
                    0,
                );
                *pout = null_mut();
            }
            return 0;
        }
    }

    len
}

pub(super) unsafe extern "C" fn fips_cleanup_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    buf: *mut c_uchar,
    len: usize,
) {
    // SAFETY: OpenSSL returns the allocation with the length from this callback.
    unsafe {
        super::provider::fips_clear_free(buf.cast::<c_void>(), len, null(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::{entropy_len, mix_nonce};

    #[test]
    fn entropy_len_uses_bits_and_checks_bounds() {
        assert_eq!(entropy_len(1, 0, 1), Some(1));
        assert_eq!(entropy_len(9, 0, 2), Some(2));
        assert_eq!(entropy_len(128, 8, 16), Some(16));
        assert_eq!(entropy_len(129, 8, 16), None);
        assert_eq!(entropy_len(-1, 0, 16), None);
        assert_eq!(entropy_len(0, 0, 16), None);
        assert_eq!(entropy_len(1, 2, 1), None);
    }

    #[test]
    fn nonce_salt_xor_preserves_byte_variation() {
        let mut nonce = [0x12, 0x34];
        mix_nonce(&mut nonce, &[0xff, 0x80]);
        assert_eq!(nonce, [0xed, 0xb4]);
        assert_ne!(nonce, [0xff, 0xff]);
    }
}

// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Entropy callbacks and source selection for the FIPS provider.

use std::ffi::{c_int, c_uchar, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::slice;

use ossl::bindings::*;

use crate::misc::{bytes_to_slice, bytes_to_slice_mut};

#[cfg(all(test, feature = "fips-jitterentropy"))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(test, feature = "fips-jitterentropy"))]
static FAIL_NEXT_ENTROPY_REQUEST: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "fips-jitterentropy")]
mod jitter;
#[cfg(not(feature = "fips-jitterentropy"))]
mod kernel;

#[cfg(all(test, feature = "fips-jitterentropy"))]
pub(crate) const ENTROPY_SOURCE: &str = "jitterentropy";
#[cfg(all(test, not(feature = "fips-jitterentropy")))]
pub(crate) const ENTROPY_SOURCE: &str = "kernel";

#[cfg(all(test, feature = "fips-jitterentropy"))]
pub(crate) fn jitter_status() -> Option<serde_json::Value> {
    let status = jitter::status()?;
    serde_json::from_str(&status).ok()
}

#[cfg(all(test, feature = "fips-jitterentropy"))]
pub(crate) fn jitter_successful_fills() -> usize {
    jitter::successful_fills()
}

#[cfg(all(test, feature = "fips-jitterentropy"))]
pub(crate) fn enable_os_rng_denial_for_test() {
    if std::env::var_os("KRYOPTIC_DENY_OS_RNG").is_none() {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                b"kryoptic_deny_os_rng_enable\0".as_ptr().cast(),
            )
        };
        assert!(!symbol.is_null(), "OS RNG denial shim is not loaded");
        // SAFETY: The preload shim exports this function with the declared ABI.
        let enable: unsafe extern "C" fn() =
            unsafe { std::mem::transmute(symbol) };
        // SAFETY: The shim function takes no arguments and has no preconditions.
        unsafe { enable() };
        let mut probe = 0_u8;
        // SAFETY: The probe points to one writable byte for this call.
        let result =
            unsafe { libc::getrandom((&mut probe as *mut u8).cast(), 1, 0) };
        assert_eq!(result, -1, "the OS RNG denial shim must reject getrandom");
        assert!(
            denied_os_rng_calls_for_test() > 0,
            "the OS RNG denial shim must record the rejected call"
        );
    }
    #[cfg(not(target_os = "linux"))]
    panic!("OS RNG denial test shim is only available on Linux");
}

#[cfg(all(test, feature = "fips-jitterentropy"))]
pub(crate) fn denied_os_rng_calls_for_test() -> u64 {
    if std::env::var_os("KRYOPTIC_DENY_OS_RNG").is_none() {
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                b"kryoptic_os_rng_denial_count\0".as_ptr().cast(),
            )
        };
        assert!(!symbol.is_null(), "OS RNG denial shim is not loaded");
        // SAFETY: The preload shim exports this function with the declared ABI.
        let count: unsafe extern "C" fn() -> libc::c_ulong =
            unsafe { std::mem::transmute(symbol) };
        // SAFETY: The shim function takes no arguments and returns a counter.
        unsafe { count() as u64 }
    }
    #[cfg(not(target_os = "linux"))]
    panic!("OS RNG denial test shim is only available on Linux");
}

#[derive(Clone, Copy, Debug)]
enum EntropyError {
    Source,
}

fn fill_entropy(out: &mut [u8]) -> Result<(), EntropyError> {
    #[cfg(all(test, feature = "fips-jitterentropy"))]
    if FAIL_NEXT_ENTROPY_REQUEST.swap(false, Ordering::SeqCst) {
        return Err(EntropyError::Source);
    }

    match catch_unwind(AssertUnwindSafe(|| {
        #[cfg(feature = "fips-jitterentropy")]
        return jitter::fill(out);
        #[cfg(not(feature = "fips-jitterentropy"))]
        return kernel::fill(out);
    })) {
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
    #[cfg(feature = "fips-jitterentropy")]
    use std::ptr::{null, null_mut};
    #[cfg(feature = "fips-jitterentropy")]
    use std::slice;
    #[cfg(feature = "fips-jitterentropy")]
    use std::sync::atomic::Ordering;

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
    fn one_fips_entropy_source_is_selected() {
        #[cfg(feature = "fips-jitterentropy")]
        assert_eq!(super::ENTROPY_SOURCE, "jitterentropy");
        #[cfg(not(feature = "fips-jitterentropy"))]
        assert_eq!(super::ENTROPY_SOURCE, "kernel");
    }

    #[cfg(feature = "fips-jitterentropy")]
    #[test]
    fn imported_jent_api_resolves_from_the_expected_shared_object() {
        super::enable_os_rng_denial_for_test();
        let library_dir = std::env::var("KRYOPTIC_JITTERENTROPY_LIB_DIR")
            .expect("the test sets the JENT package directory");
        let expected = std::fs::canonicalize(
            std::path::Path::new(&library_dir).join(super::jitter::soname()),
        )
        .expect("the expected JENT library exists");
        let loaded_paths = super::jitter::imported_api_library_paths();
        assert_eq!(loaded_paths.len(), 6);
        for path in loaded_paths {
            let loaded = std::fs::canonicalize(
                path.expect("the loader identifies each imported JENT symbol"),
            )
            .expect("the imported JENT library path exists");
            assert_eq!(loaded, expected);
        }
    }

    #[cfg(feature = "fips-jitterentropy")]
    #[test]
    #[ignore = "runs in a process with a JENT header version mismatch"]
    fn jent_header_version_mismatch_sets_fips_error_state() {
        let result = crate::rng::RNG::new("HMAC DRBG SHA256");
        assert!(result.is_err());
        assert!(!crate::fips::check_fips_state_ok());
    }

    #[test]
    fn nonce_salt_xor_preserves_byte_variation() {
        let mut nonce = [0x12, 0x34];
        mix_nonce(&mut nonce, &[0xff, 0x80]);
        assert_eq!(nonce, [0xed, 0xb4]);
        assert_ne!(nonce, [0xff, 0xff]);
    }

    #[cfg(feature = "fips-jitterentropy")]
    #[test]
    fn entropy_callback_uses_jitterentropy_with_fips_health_tests() {
        super::enable_os_rng_denial_for_test();
        let initial_fills = super::jitter::successful_fills();
        let mut output = null_mut();
        // SAFETY: The callback writes a new output pointer into `output`.
        let length = unsafe {
            super::fips_get_entropy(null(), &mut output, 129, 16, 32)
        };
        assert_eq!(length, 17);
        assert!(!output.is_null());

        // SAFETY: The callback returned a 17-byte allocation owned by this test.
        let bytes = unsafe { slice::from_raw_parts(output, length) };
        assert!(bytes.iter().any(|byte| *byte != 0));

        let status = super::jitter_status().expect("JENT status is available");
        assert_eq!(status["configuration"]["fipsMode"], true);
        assert_eq!(status["configuration"]["secureMemory"], true);
        assert_eq!(status["configuration"]["internalTimer"], false);
        assert_eq!(status["configuration"]["flags"]["JENT_FORCE_FIPS"], true);
        assert_eq!(
            status["configuration"]["flags"]["JENT_DISABLE_INTERNAL_TIMER"],
            true
        );
        assert!(super::jitter::successful_fills() > initial_fills);
        // SAFETY: This test owns the callback allocation and passes its length.
        unsafe { super::fips_cleanup_entropy(null(), output, length) };
    }

    #[cfg(feature = "fips-jitterentropy")]
    #[test]
    #[ignore = "sets the process-wide FIPS error state"]
    fn entropy_source_failure_sets_the_fips_error_state() {
        super::enable_os_rng_denial_for_test();
        let _rng = crate::rng::RNG::new("HMAC DRBG SHA256")
            .expect("the provider is initialized");
        super::FAIL_NEXT_ENTROPY_REQUEST.store(true, Ordering::SeqCst);

        let mut output = null_mut();
        // SAFETY: The callback writes the output pointer for this request.
        let length = unsafe {
            super::fips_get_entropy(null(), &mut output, 256, 16, 32)
        };
        assert_eq!(length, 0);
        assert!(output.is_null());
        assert!(!crate::fips::check_fips_state_ok());

        let mut random_output = [0xa5; 32];
        let error = crate::get_random_data(&mut random_output)
            .expect_err("the failed FIPS provider rejects random output");
        assert_eq!(error.rv(), crate::pkcs11::CKR_DEVICE_ERROR);
        assert_eq!(random_output, [0; 32]);
    }

    #[cfg(feature = "fips-jitterentropy")]
    #[test]
    fn drbg_instantiation_and_reseed_request_jent_entropy() {
        super::enable_os_rng_denial_for_test();
        let initial_fills = super::jitter::successful_fills();
        let mut rng = crate::rng::RNG::new("HMAC DRBG SHA256")
            .expect("the parentless HMAC-DRBG initializes");
        let after_instantiate = super::jitter::successful_fills();
        assert!(after_instantiate > initial_fills);

        rng.add_seed(b"PKCS11 additional input")
            .expect("the DRBG reseeds with caller input");
        let after_reseed = super::jitter::successful_fills();
        assert!(after_reseed > after_instantiate);

        let mut output = [0; 32];
        rng.generate_random(&mut output)
            .expect("the DRBG generates output");
        assert!(output.iter().any(|byte| *byte != 0));
    }
}

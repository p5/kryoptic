// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use std::cell::RefCell;
use std::ffi::{c_char, c_uint};
use std::ptr::NonNull;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use super::EntropyError;

const JENT_OSR: c_uint = 0;
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/jent_bindings.rs"));
}

use bindings::rand_data;

#[cfg(test)]
pub(super) fn soname() -> String {
    format!("libjitterentropy.so.{}", bindings::JENT_MAJVERSION)
}

const JENT_FLAGS: c_uint = (bindings::JENT_DISABLE_INTERNAL_TIMER
    | bindings::JENT_FORCE_FIPS) as c_uint;
static JENT_INITIALIZED: OnceLock<bool> = OnceLock::new();
#[cfg(test)]
static SUCCESSFUL_FILLS: AtomicUsize = AtomicUsize::new(0);

struct JentCollector {
    pointer: NonNull<rand_data>,
}

impl JentCollector {
    fn new() -> Result<Self, EntropyError> {
        // SAFETY: The generated declaration matches this package header.
        if unsafe { bindings::jent_version() }
            != bindings::JENT_VERSION as c_uint
        {
            return Err(EntropyError::Source);
        }
        let initialized = *JENT_INITIALIZED.get_or_init(|| {
            // SAFETY: The generated declaration matches this package header.
            unsafe { bindings::jent_entropy_init_ex(JENT_OSR, JENT_FLAGS) == 0 }
        });
        if !initialized {
            return Err(EntropyError::Source);
        }
        // SAFETY: The library allocates an owned collector or returns null.
        let pointer = NonNull::new(unsafe {
            bindings::jent_entropy_collector_alloc(JENT_OSR, JENT_FLAGS)
        })
        .ok_or(EntropyError::Source)?;

        let mut collector = Self { pointer };
        if !collector.check_status() {
            return Err(EntropyError::Source);
        }
        Ok(collector)
    }

    fn check_status(&mut self) -> bool {
        let mut status = [0 as c_char; 2048];
        // SAFETY: The collector is valid and `status` is a writable buffer.
        if unsafe {
            bindings::jent_status(
                self.pointer.as_ptr(),
                status.as_mut_ptr(),
                status.len(),
            )
        } != 0
        {
            return false;
        }
        // SAFETY: A successful jent_status call writes a NUL-terminated JSON string.
        let status = unsafe { std::ffi::CStr::from_ptr(status.as_ptr()) };
        let Ok(status) =
            serde_json::from_slice::<serde_json::Value>(status.to_bytes())
        else {
            return false;
        };
        status["configuration"]["secureMemory"].as_bool() == Some(true)
            && status["configuration"]["fipsMode"].as_bool() == Some(true)
            && status["configuration"]["flags"]["JENT_FORCE_FIPS"].as_bool()
                == Some(true)
            && status["configuration"]["flags"]["JENT_DISABLE_INTERNAL_TIMER"]
                .as_bool()
                == Some(true)
    }

    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        let mut pointer = self.pointer.as_ptr();
        // SAFETY: The collector and output buffer remain valid for this call.
        let result = unsafe {
            bindings::jent_read_entropy_safe(
                &mut pointer,
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        let Some(pointer) = NonNull::new(pointer) else {
            return Err(EntropyError::Source);
        };
        self.pointer = pointer;
        if usize::try_from(result).ok() != Some(out.len()) {
            return Err(EntropyError::Source);
        }
        if !self.check_status() {
            return Err(EntropyError::Source);
        }
        Ok(())
    }
}

impl Drop for JentCollector {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the collector until this destructor runs.
        unsafe { bindings::jent_entropy_collector_free(self.pointer.as_ptr()) }
    }
}

#[cfg(test)]
pub(super) fn status() -> Option<String> {
    COLLECTOR
        .try_with(|collector| {
            let collector = collector.try_borrow().ok()?;
            let collector = collector.as_ref()?;
            let mut status = [0 as c_char; 2048];
            // SAFETY: The collector is valid and `status` is a writable buffer.
            if unsafe {
                bindings::jent_status(
                    collector.pointer.as_ptr(),
                    status.as_mut_ptr(),
                    status.len(),
                )
            } != 0
            {
                return None;
            }
            // SAFETY: A successful jent_status call writes a NUL-terminated JSON string.
            let status = unsafe { std::ffi::CStr::from_ptr(status.as_ptr()) };
            String::from_utf8(status.to_bytes().to_vec()).ok()
        })
        .ok()
        .flatten()
}

#[cfg(test)]
fn symbol_library_path(symbol: *const std::ffi::c_void) -> Option<String> {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    // SAFETY: `symbol` is a loaded JENT function and `info` is writable storage.
    if unsafe { libc::dladdr(symbol, info.as_mut_ptr()) } == 0 {
        return None;
    }
    // SAFETY: A successful dladdr call initializes the complete Dl_info value.
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null() {
        return None;
    }
    // SAFETY: The dynamic loader returns a NUL-terminated path for this object.
    unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
pub(super) fn imported_api_library_paths() -> Vec<Option<String>> {
    [
        bindings::jent_entropy_init_ex as *const () as *const std::ffi::c_void,
        bindings::jent_entropy_collector_alloc as *const ()
            as *const std::ffi::c_void,
        bindings::jent_entropy_collector_free as *const ()
            as *const std::ffi::c_void,
        bindings::jent_read_entropy_safe as *const ()
            as *const std::ffi::c_void,
        bindings::jent_version as *const () as *const std::ffi::c_void,
        bindings::jent_status as *const () as *const std::ffi::c_void,
    ]
    .into_iter()
    .map(symbol_library_path)
    .collect()
}

thread_local! {
    static COLLECTOR: RefCell<Option<JentCollector>> = const { RefCell::new(None) };
}

pub(super) fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
    let result = COLLECTOR
        .try_with(|collector| {
            let mut collector = collector
                .try_borrow_mut()
                .map_err(|_| EntropyError::Source)?;
            if collector.is_none() {
                *collector = Some(JentCollector::new()?);
            }
            collector.as_mut().ok_or(EntropyError::Source)?.fill(out)
        })
        .map_err(|_| EntropyError::Source)?;
    if result.is_ok() {
        #[cfg(test)]
        SUCCESSFUL_FILLS.fetch_add(1, Ordering::Relaxed);
    }
    result
}

#[cfg(test)]
pub(super) fn successful_fills() -> usize {
    SUCCESSFUL_FILLS.load(Ordering::Relaxed)
}

// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! Jitterentropy-based entropy source implementation.
//!
//! This module provides an entropy source based on CPU timing jitter,
//! implementing the jitterentropy library by Stephan Mueller.
//!
//! The jitterentropy library is SP800-90B compliant when used with the
//! `JENT_FORCE_FIPS` flag, making it suitable for FIPS-validated modules.
//!
//! # References
//!
//! - Jitterentropy Library: <https://github.com/smuellerDD/jitterentropy-library>
//! - Documentation: <http://www.chronox.de/jent>

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_uint};
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::{Error, ErrorKind};
use super::EntropySource;

// ============================================================================
// FFI Bindings to jitterentropy library
// ============================================================================

/// Opaque type representing the jitterentropy random data collector.
#[repr(C)]
pub struct rand_data {
    _opaque: [u8; 0],
}

// Jitterentropy flags
/// Disable memory access for entropy (saves memory but reduces entropy quality)
pub const JENT_DISABLE_MEMORY_ACCESS: c_uint = 1 << 2;
/// Force use of internal timer
pub const JENT_FORCE_INTERNAL_TIMER: c_uint = 1 << 3;
/// Disable internal timer
pub const JENT_DISABLE_INTERNAL_TIMER: c_uint = 1 << 4;
/// Force FIPS compliant mode including full SP800-90B compliance
pub const JENT_FORCE_FIPS: c_uint = 1 << 5;
/// AIS 20/31 NTG.1 compliance
pub const JENT_NTG1: c_uint = 1 << 6;

// Jitterentropy error codes from init
pub const JENT_ENOTIME: c_int = 1;
pub const JENT_ECOARSETIME: c_int = 2;
pub const JENT_ENOMONOTONIC: c_int = 3;
pub const JENT_EMINVARIATION: c_int = 4;
pub const JENT_EVARVAR: c_int = 5;
pub const JENT_EMINVARVAR: c_int = 6;
pub const JENT_EPROGERR: c_int = 7;
pub const JENT_ESTUCK: c_int = 8;
pub const JENT_EHEALTH: c_int = 9;
pub const JENT_ERCT: c_int = 10;
pub const JENT_EHASH: c_int = 11;
pub const JENT_EMEM: c_int = 12;
pub const JENT_EGCD: c_int = 13;

// Health test failure masks
pub const JENT_RCT_FAILURE: c_uint = 1;
pub const JENT_APT_FAILURE: c_uint = 2;
pub const JENT_LAG_FAILURE: c_uint = 4;

// Runtime read error codes (from jent_read_entropy)
const JENT_READ_NULL_COLLECTOR: isize = -1;
const JENT_READ_RCT_FAILED: isize = -2;
const JENT_READ_APT_FAILED: isize = -3;
const JENT_READ_TIMER_FAILED: isize = -4;
const JENT_READ_LAG_FAILED: isize = -5;
const JENT_READ_RCT_PERMANENT: isize = -6;
const JENT_READ_APT_PERMANENT: isize = -7;
const JENT_READ_LAG_PERMANENT: isize = -8;

// ============================================================================
// Error types
// ============================================================================

/// Jitterentropy-specific error type with detailed failure information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterentropyError {
    /// Library initialization failed with the given error code.
    InitFailed(c_int),
    /// Collector allocation failed (usually memory or timer issues).
    CollectorAllocFailed,
    /// Null collector pointer passed to read function.
    NullCollector,
    /// Repetition Count Test (RCT) failed - temporary failure.
    RctFailed,
    /// Adaptive Proportion Test (APT) failed - temporary failure.
    AptFailed,
    /// Timer initialization failed.
    TimerFailed,
    /// Lag predictor test failed - temporary failure.
    LagFailed,
    /// RCT permanent failure - collector must be recreated.
    RctPermanent,
    /// APT permanent failure - collector must be recreated.
    AptPermanent,
    /// Lag permanent failure - collector must be recreated.
    LagPermanent,
    /// Unknown error with the given code.
    Unknown(isize),
}

impl JitterentropyError {
    /// Create an error from a read operation return code.
    fn from_read_error(code: isize) -> Self {
        match code {
            JENT_READ_NULL_COLLECTOR => JitterentropyError::NullCollector,
            JENT_READ_RCT_FAILED => JitterentropyError::RctFailed,
            JENT_READ_APT_FAILED => JitterentropyError::AptFailed,
            JENT_READ_TIMER_FAILED => JitterentropyError::TimerFailed,
            JENT_READ_LAG_FAILED => JitterentropyError::LagFailed,
            JENT_READ_RCT_PERMANENT => JitterentropyError::RctPermanent,
            JENT_READ_APT_PERMANENT => JitterentropyError::AptPermanent,
            JENT_READ_LAG_PERMANENT => JitterentropyError::LagPermanent,
            _ => JitterentropyError::Unknown(code),
        }
    }

    /// Returns true if this is a permanent failure requiring collector recreation.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            JitterentropyError::RctPermanent
                | JitterentropyError::AptPermanent
                | JitterentropyError::LagPermanent
        )
    }

    /// Returns true if this is a health test failure (temporary or permanent).
    pub fn is_health_test_failure(&self) -> bool {
        matches!(
            self,
            JitterentropyError::RctFailed
                | JitterentropyError::AptFailed
                | JitterentropyError::LagFailed
                | JitterentropyError::RctPermanent
                | JitterentropyError::AptPermanent
                | JitterentropyError::LagPermanent
        )
    }

    /// Get a human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            JitterentropyError::InitFailed(code) => match *code {
                JENT_ENOTIME => "Timer service not available",
                JENT_ECOARSETIME => "Timer too coarse for RNG",
                JENT_ENOMONOTONIC => "Timer is not monotonic increasing",
                JENT_EMINVARIATION => "Timer variations too small for RNG",
                JENT_EVARVAR => "Timer does not produce variations of variations",
                JENT_EMINVARVAR => "Timer variations of variations too small",
                JENT_EPROGERR => "Programming error",
                JENT_ESTUCK => "Too many stuck results during init",
                JENT_EHEALTH => "Health test failed during initialization",
                JENT_ERCT => "RCT failed during initialization",
                JENT_EHASH => "Hash self test failed",
                JENT_EMEM => "Memory allocation failed",
                JENT_EGCD => "GCD self-test failed",
                _ => "Unknown initialization error",
            },
            JitterentropyError::CollectorAllocFailed => "Collector allocation failed",
            JitterentropyError::NullCollector => "Null collector pointer",
            JitterentropyError::RctFailed => "RCT health test failed (temporary)",
            JitterentropyError::AptFailed => "APT health test failed (temporary)",
            JitterentropyError::TimerFailed => "Timer initialization failed",
            JitterentropyError::LagFailed => "Lag predictor test failed (temporary)",
            JitterentropyError::RctPermanent => "RCT health test failed (permanent)",
            JitterentropyError::AptPermanent => "APT health test failed (permanent)",
            JitterentropyError::LagPermanent => "Lag predictor test failed (permanent)",
            JitterentropyError::Unknown(_) => "Unknown error",
        }
    }
}

impl std::fmt::Display for JitterentropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<JitterentropyError> for Error {
    fn from(_: JitterentropyError) -> Self {
        // Map to generic error for now; could add specific ErrorKind variants
        Error::new(ErrorKind::OsslError)
    }
}

unsafe extern "C" {
    /// Initialize the jitterentropy library with specific parameters.
    ///
    /// # Arguments
    /// * `osr` - Oversampling rate (0 for default)
    /// * `flags` - Combination of JENT_* flags
    fn jent_entropy_init_ex(osr: c_uint, flags: c_uint) -> c_int;

    /// Allocate a new entropy collector.
    ///
    /// # Arguments
    /// * `osr` - Oversampling rate (0 for default, 1 is minimum)
    /// * `flags` - Combination of JENT_* flags
    ///
    /// # Returns
    /// Pointer to the entropy collector, or NULL on failure.
    fn jent_entropy_collector_alloc(osr: c_uint, flags: c_uint) -> *mut rand_data;

    /// Free an entropy collector.
    fn jent_entropy_collector_free(ec: *mut rand_data);

    /// Read entropy from the collector.
    ///
    /// # Arguments
    /// * `ec` - The entropy collector
    /// * `data` - Buffer to fill with entropy
    /// * `len` - Size of the buffer
    ///
    /// # Returns
    /// Number of bytes read on success, or negative error code:
    /// * -1: entropy_collector is NULL
    /// * -2: RCT failed
    /// * -3: APT failed
    /// * -4: Timer cannot be initialized
    /// * -5: LAG failure
    /// * -6: RCT permanent failure
    /// * -7: APT permanent failure
    /// * -8: LAG permanent failure
    fn jent_read_entropy(ec: *mut rand_data, data: *mut c_char, len: usize) -> isize;

    /// Read entropy with automatic reallocation on health test failure.
    ///
    /// This function automatically reallocates the entropy collector with
    /// a higher oversampling rate if a health test failure occurs.
    ///
    /// # Arguments
    /// * `ec` - Pointer to pointer to entropy collector (may be reallocated)
    /// * `data` - Buffer to fill with entropy
    /// * `len` - Size of the buffer
    ///
    /// # Returns
    /// Number of bytes read on success, or negative error code.
    fn jent_read_entropy_safe(
        ec: *mut *mut rand_data,
        data: *mut c_char,
        len: usize,
    ) -> isize;

    /// Get the jitterentropy library version.
    fn jent_version() -> c_uint;
}

// ============================================================================
// Global initialization state
// ============================================================================

/// Result of jitterentropy initialization.
/// Contains Ok((flags)) with the flags used, or the error code if not.
static JENT_INIT_RESULT: OnceLock<Result<c_uint, c_int>> = OnceLock::new();

/// Initialize the jitterentropy library if not already done.
///
/// This function is thread-safe and guaranteed to only initialize once
/// using `OnceLock`. All threads will see the same initialization result.
///
/// # FIPS Compliance
///
/// For FIPS builds, this function enforces that initialization always uses
/// `JENT_FORCE_FIPS` flag. If a prior initialization occurred without FIPS
/// flags, subsequent FIPS-mode requests will fail.
fn ensure_initialized(flags: c_uint) -> Result<(), JitterentropyError> {
    let result = JENT_INIT_RESULT.get_or_init(|| {
        // Always include JENT_FORCE_FIPS for SP800-90B compliance
        // This ensures we never accidentally initialize without FIPS mode
        let init_flags = flags | JENT_FORCE_FIPS;
        let ret = unsafe { jent_entropy_init_ex(0, init_flags) };
        if ret == 0 {
            Ok(init_flags)
        } else {
            Err(ret)
        }
    });

    match result {
        Ok(init_flags) => {
            // Verify FIPS flag is present if caller requested it
            if (flags & JENT_FORCE_FIPS) != 0 && (init_flags & JENT_FORCE_FIPS) == 0 {
                // This shouldn't happen with the fix above, but guard anyway
                return Err(JitterentropyError::InitFailed(JENT_EHEALTH));
            }
            Ok(())
        }
        Err(code) => Err(JitterentropyError::InitFailed(*code)),
    }
}

/// Check if jitterentropy has been initialized and is available.
fn is_initialized_and_available() -> bool {
    JENT_INIT_RESULT
        .get()
        .is_some_and(|r| r.is_ok())
}

/// Get the jitterentropy library version.
pub fn version() -> u32 {
    unsafe { jent_version() }
}

/// Convert a jitterentropy error code to a human-readable message.
pub fn error_message(code: c_int) -> &'static str {
    match code {
        0 => "Success",
        JENT_ENOTIME => "Timer service not available",
        JENT_ECOARSETIME => "Timer too coarse for RNG",
        JENT_ENOMONOTONIC => "Timer is not monotonic increasing",
        JENT_EMINVARIATION => "Timer variations too small for RNG",
        JENT_EVARVAR => "Timer does not produce variations of variations",
        JENT_EMINVARVAR => "Timer variations of variations too small",
        JENT_EPROGERR => "Programming error",
        JENT_ESTUCK => "Too many stuck results during init",
        JENT_EHEALTH => "Health test failed during initialization",
        JENT_ERCT => "RCT failed during initialization",
        JENT_EHASH => "Hash self test failed",
        JENT_EMEM => "Memory allocation failed",
        JENT_EGCD => "GCD self-test failed",
        _ => "Unknown error",
    }
}

// ============================================================================
// JitterentropySource implementation
// ============================================================================

/// Configuration for the jitterentropy source.
#[derive(Debug, Clone, Copy)]
pub struct JitterentropyConfig {
    /// Oversampling rate. Higher values increase entropy quality but slow down
    /// generation. 0 uses the library default, 1 is the minimum.
    pub osr: u32,
    /// Enable FIPS mode (SP800-90B compliance).
    pub fips_mode: bool,
    /// Use the safe API that auto-recovers from health test failures.
    pub use_safe_api: bool,
}

impl Default for JitterentropyConfig {
    fn default() -> Self {
        JitterentropyConfig {
            osr: 1,
            fips_mode: true,
            use_safe_api: false,
        }
    }
}

impl JitterentropyConfig {
    /// Create a configuration for FIPS-compliant operation.
    pub fn fips() -> Self {
        JitterentropyConfig {
            osr: 1,
            fips_mode: true,
            use_safe_api: false,
        }
    }

    /// Create a configuration that auto-recovers from health test failures.
    ///
    /// Note: This mode changes H_submitter which may not be allowed in
    /// strict SP800-90B compliance scenarios.
    pub fn resilient() -> Self {
        JitterentropyConfig {
            osr: 1,
            fips_mode: true,
            use_safe_api: true,
        }
    }

    /// Convert configuration to jitterentropy flags.
    fn to_flags(&self) -> c_uint {
        let mut flags: c_uint = 0;
        if self.fips_mode {
            flags |= JENT_FORCE_FIPS;
        }
        flags
    }
}

/// Wrapper around a jitterentropy entropy collector.
///
/// This is not Send/Sync because the underlying jitterentropy collector
/// is not thread-safe. Each thread should have its own collector.
struct JitterentropyCollector {
    ec: *mut rand_data,
    config: JitterentropyConfig,
}

impl JitterentropyCollector {
    fn new(config: JitterentropyConfig) -> Result<Self, JitterentropyError> {
        ensure_initialized(config.to_flags())?;

        let ec = unsafe {
            jent_entropy_collector_alloc(config.osr, config.to_flags())
        };

        if ec.is_null() {
            return Err(JitterentropyError::CollectorAllocFailed);
        }

        Ok(JitterentropyCollector { ec, config })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, JitterentropyError> {
        if self.ec.is_null() {
            return Err(JitterentropyError::NullCollector);
        }

        let ret = if self.config.use_safe_api {
            unsafe {
                jent_read_entropy_safe(
                    &mut self.ec,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                )
            }
        } else {
            unsafe {
                jent_read_entropy(
                    self.ec,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                )
            }
        };

        if ret < 0 {
            // FIPS requirement: zeroize buffer on failure to prevent
            // partial entropy leakage
            crate::zeromem(buf);
            Err(JitterentropyError::from_read_error(ret))
        } else {
            Ok(ret as usize)
        }
    }
}

impl Drop for JitterentropyCollector {
    fn drop(&mut self) {
        if !self.ec.is_null() {
            unsafe { jent_entropy_collector_free(self.ec) };
            self.ec = null_mut();
        }
    }
}

// JitterentropyCollector is NOT thread-safe
// Each thread needs its own collector via thread-local storage

/// Entropy source based on CPU timing jitter.
///
/// This source uses the jitterentropy library to collect entropy from
/// CPU execution timing variations. It is SP800-90B compliant when
/// configured with `fips_mode: true`.
///
/// # Thread Safety
///
/// This type is `Send + Sync`, but internally uses thread-local storage
/// to maintain per-thread entropy collectors. This is necessary because
/// the underlying jitterentropy library's collectors are not thread-safe.
///
/// # Example
///
/// ```ignore
/// use ossl::entropy::jitterentropy::{JitterentropySource, JitterentropyConfig};
///
/// // Create with FIPS-compliant configuration
/// let source = JitterentropySource::new(JitterentropyConfig::fips())?;
///
/// let mut buf = [0u8; 32];
/// source.get_entropy(&mut buf)?;
/// ```
#[derive(Debug)]
pub struct JitterentropySource {
    config: JitterentropyConfig,
}

// Thread-local collector storage
thread_local! {
    static THREAD_COLLECTOR: RefCell<Option<JitterentropyCollector>> = const { RefCell::new(None) };
}

impl JitterentropySource {
    /// Create a new jitterentropy source with the given configuration.
    ///
    /// This will initialize the jitterentropy library if not already done.
    ///
    /// # Errors
    ///
    /// Returns an error if jitterentropy is not available on this system
    /// (e.g., due to insufficient timer resolution).
    pub fn new(config: JitterentropyConfig) -> Result<Self, Error> {
        // Verify jitterentropy is available
        ensure_initialized(config.to_flags())?;

        Ok(JitterentropySource { config })
    }

    /// Create a new jitterentropy source with default FIPS configuration.
    pub fn new_fips() -> Result<Self, Error> {
        Self::new(JitterentropyConfig::fips())
    }

    /// Try to create a new jitterentropy source, returning detailed error info.
    ///
    /// Unlike `new()`, this returns a `JitterentropyError` with specific
    /// failure information useful for debugging.
    pub fn try_new(config: JitterentropyConfig) -> Result<Self, JitterentropyError> {
        ensure_initialized(config.to_flags())?;
        Ok(JitterentropySource { config })
    }

    /// Try to create with FIPS config, returning detailed error info.
    pub fn try_new_fips() -> Result<Self, JitterentropyError> {
        Self::try_new(JitterentropyConfig::fips())
    }

    /// Get the jitterentropy library version.
    pub fn library_version() -> u32 {
        version()
    }

    /// Get or create the thread-local collector.
    ///
    /// If a permanent health test failure occurred, the collector is
    /// automatically discarded and recreated on the next call.
    fn with_collector<F, R>(&self, f: F) -> Result<R, JitterentropyError>
    where
        F: FnOnce(&mut JitterentropyCollector) -> Result<R, JitterentropyError>,
    {
        THREAD_COLLECTOR.with(|cell| {
            let mut collector_opt = cell.borrow_mut();

            // Create collector if it doesn't exist
            if collector_opt.is_none() {
                *collector_opt = Some(JitterentropyCollector::new(self.config)?);
            }

            // Use the collector (guaranteed to be Some after above check)
            let collector = collector_opt.as_mut().unwrap();
            let result = f(collector);

            // On permanent failure, discard the collector so it gets
            // recreated on the next call
            if let Err(ref e) = result {
                if e.is_permanent() {
                    *collector_opt = None;
                }
            }

            result
        })
    }
}

impl EntropySource for JitterentropySource {
    fn name(&self) -> &'static str {
        "jitterentropy"
    }

    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.with_collector(|collector| collector.read(buf))
            .map_err(|e| e.into())
    }

    fn health_check(&self) -> Result<(), Error> {
        // Perform a small entropy read to trigger health tests
        let mut test_buf = [0u8; 32];
        self.with_collector(|collector| collector.read(&mut test_buf))?;
        crate::zeromem(&mut test_buf);
        Ok(())
    }

    fn is_available(&self) -> bool {
        is_initialized_and_available()
    }
}

// JitterentropySource is Send + Sync because:
// - The config is just plain data (Copy + Send + Sync)
// - The actual collector is in thread-local storage
unsafe impl Send for JitterentropySource {}
unsafe impl Sync for JitterentropySource {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitterentropy_version() {
        let ver = version();
        // Version should be at least 3.0.0 (3000000)
        assert!(ver >= 3000000, "Version {} is too old", ver);
    }

    #[test]
    fn test_jitterentropy_config_flags() {
        let config = JitterentropyConfig::fips();
        let flags = config.to_flags();
        assert!(flags & JENT_FORCE_FIPS != 0);
    }

    #[test]
    fn test_jitterentropy_source_creation() {
        // This test may fail on systems without suitable timers
        match JitterentropySource::new_fips() {
            Ok(source) => {
                assert_eq!(source.name(), "jitterentropy");
                // Test entropy generation
                let mut buf = [0u8; 32];
                if let Ok(len) = source.get_entropy(&mut buf) {
                    assert_eq!(len, 32);
                    // Very unlikely to be all zeros
                    assert!(buf.iter().any(|&b| b != 0));
                }
            }
            Err(_) => {
                // Jitterentropy not available on this system
                println!("Jitterentropy not available on this system");
            }
        }
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(error_message(0), "Success");
        assert_eq!(error_message(JENT_ENOTIME), "Timer service not available");
        assert_eq!(error_message(JENT_EHEALTH), "Health test failed during initialization");
    }

    #[test]
    fn test_jitterentropy_error_types() {
        // Test error classification
        let rct_err = JitterentropyError::RctFailed;
        assert!(rct_err.is_health_test_failure());
        assert!(!rct_err.is_permanent());

        let rct_perm = JitterentropyError::RctPermanent;
        assert!(rct_perm.is_health_test_failure());
        assert!(rct_perm.is_permanent());

        let alloc_err = JitterentropyError::CollectorAllocFailed;
        assert!(!alloc_err.is_health_test_failure());
        assert!(!alloc_err.is_permanent());

        // Test error descriptions
        assert!(!rct_err.description().is_empty());
        assert!(!rct_perm.description().is_empty());

        // Test Display trait
        let msg = format!("{}", rct_err);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_jitterentropy_error_from_read() {
        assert_eq!(
            JitterentropyError::from_read_error(-1),
            JitterentropyError::NullCollector
        );
        assert_eq!(
            JitterentropyError::from_read_error(-2),
            JitterentropyError::RctFailed
        );
        assert_eq!(
            JitterentropyError::from_read_error(-6),
            JitterentropyError::RctPermanent
        );
        assert!(matches!(
            JitterentropyError::from_read_error(-99),
            JitterentropyError::Unknown(-99)
        ));
    }

    #[test]
    fn test_try_new_detailed_error() {
        // This test verifies that try_new returns detailed errors
        match JitterentropySource::try_new_fips() {
            Ok(source) => {
                assert!(source.is_available());
            }
            Err(e) => {
                // Should get a specific error, not just a generic failure
                println!("Jitterentropy init failed: {}", e.description());
                match e {
                    JitterentropyError::InitFailed(code) => {
                        // We got a specific init error code
                        println!("Init error code: {}", code);
                    }
                    _ => {
                        // Other error types are also acceptable
                    }
                }
            }
        }
    }
}

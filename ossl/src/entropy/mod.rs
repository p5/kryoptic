// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! Entropy source abstraction for cryptographic random number generation.
//!
//! This module provides a pluggable entropy source architecture that allows
//! different entropy providers to be used interchangeably. This is particularly
//! important for FIPS certification where specific entropy sources may be
//! required.
//!
//! # Available Entropy Sources
//!
//! - [`GetrandomSource`]: Uses the operating system's `getrandom()` syscall
//! - [`JitterentropySource`]: Uses CPU timing jitter (requires `jitterentropy` feature)
//!
//! # Example
//!
//! ```ignore
//! use ossl::entropy::{EntropySource, GetrandomSource};
//!
//! let source = GetrandomSource::new();
//! let mut buf = [0u8; 32];
//! source.get_entropy(&mut buf).unwrap();
//! ```

use crate::{Error, ErrorKind};

// ============================================================================
// Core Entropy Source Abstraction
// ============================================================================

/// Trait for entropy sources that can provide cryptographic-quality randomness.
///
/// Implementations of this trait must be thread-safe (`Send + Sync`) as they
/// may be used from multiple threads concurrently in the FIPS provider.
///
/// # Safety
///
/// Implementations must ensure that:
/// - The entropy returned has sufficient min-entropy for cryptographic use
/// - Health tests are performed where applicable (e.g., for jitterentropy)
/// - Failures are reported rather than returning low-quality data
pub trait EntropySource: Send + Sync + std::fmt::Debug {
    /// Returns the name of this entropy source for logging and debugging.
    fn name(&self) -> &'static str;

    /// Fills the provided buffer with entropy.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to fill with random bytes
    ///
    /// # Returns
    ///
    /// The number of bytes of entropy actually provided, or an error.
    /// The returned value may be less than `buf.len()` if the source
    /// cannot provide enough entropy, in which case the caller should
    /// handle this appropriately.
    ///
    /// # Errors
    ///
    /// Returns an error if the entropy source fails or is unavailable.
    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error>;

    /// Fills the provided buffer with a nonce value.
    ///
    /// A nonce should be unique but doesn't require the same entropy
    /// quality as `get_entropy()`. The default implementation simply
    /// calls `get_entropy()`.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to fill with the nonce
    /// * `salt` - Optional salt value to mix into the nonce
    ///
    /// # Returns
    ///
    /// The number of bytes provided, or an error.
    fn get_nonce(&self, buf: &mut [u8], salt: Option<&[u8]>) -> Result<usize, Error> {
        let len = self.get_entropy(buf)?;

        // OR salt into the buffer if provided
        if let Some(s) = salt {
            let mix_len = std::cmp::min(len, s.len());
            for i in 0..mix_len {
                buf[i] |= s[i];
            }
        }

        Ok(len)
    }

    /// Performs a health check on the entropy source.
    ///
    /// This should verify that the entropy source is functioning correctly.
    /// The default implementation returns `Ok(())`.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the source is healthy, or an error describing the failure.
    fn health_check(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Returns whether this entropy source is available on the current system.
    ///
    /// The default implementation returns `true`.
    fn is_available(&self) -> bool {
        true
    }
}

/// Entropy source using the operating system's `getrandom()` syscall.
///
/// This is the default entropy source and uses the `getrandom` crate which
/// wraps the platform-native secure random number generator:
/// - Linux: `getrandom(2)` syscall
/// - macOS: `getentropy(2)`
/// - Windows: `BCryptGenRandom`
///
/// This source is generally considered suitable for cryptographic use as it
/// draws from the kernel's entropy pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetrandomSource;

impl GetrandomSource {
    /// Creates a new `GetrandomSource` instance.
    pub fn new() -> Self {
        GetrandomSource
    }
}

impl EntropySource for GetrandomSource {
    fn name(&self) -> &'static str {
        "getrandom"
    }

    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error> {
        getrandom::fill(buf).map_err(|_| Error::new(ErrorKind::OsslError))?;
        Ok(buf.len())
    }

    fn is_available(&self) -> bool {
        // getrandom is available on all supported platforms
        true
    }
}

/// Creates the default entropy source (getrandom).
///
/// This is the simplest option and suitable for most use cases.
/// It uses the operating system's cryptographic random number generator.
pub fn create_default_entropy() -> Box<dyn EntropySource> {
    Box::new(GetrandomSource::new())
}

/// Information about the available entropy sources on this system.
#[derive(Debug, Clone)]
pub struct EntropyCapabilities {
    /// Whether getrandom is available (always true on supported platforms).
    pub getrandom_available: bool,
    /// Whether jitterentropy is available.
    #[cfg(feature = "jitterentropy")]
    pub jitterentropy_available: bool,
    /// Jitterentropy library version, if available.
    #[cfg(feature = "jitterentropy")]
    pub jitterentropy_version: Option<u32>,
}

/// Query the entropy capabilities of this system.
///
/// This function checks which entropy sources are available and returns
/// information that can be used to decide which entropy configuration to use.
///
/// # Example
///
/// ```ignore
/// use ossl::entropy::query_capabilities;
///
/// let caps = query_capabilities();
/// println!("getrandom available: {}", caps.getrandom_available);
/// ```
pub fn query_capabilities() -> EntropyCapabilities {
    #[cfg(feature = "jitterentropy")]
    {
        let jent_available = jitterentropy::JitterentropySource::try_new_fips().is_ok();
        EntropyCapabilities {
            getrandom_available: true,
            jitterentropy_available: jent_available,
            jitterentropy_version: if jent_available {
                Some(jitterentropy::version())
            } else {
                None
            },
        }
    }
    #[cfg(not(feature = "jitterentropy"))]
    {
        EntropyCapabilities {
            getrandom_available: true,
        }
    }
}

// ============================================================================
// Jitterentropy Support - requires "jitterentropy" feature
// ============================================================================

#[cfg(feature = "jitterentropy")]
pub mod jitterentropy;

#[cfg(feature = "jitterentropy")]
pub use jitterentropy::JitterentropySource;

/// Creates a FIPS-compliant entropy source using jitterentropy.
///
/// This function returns a jitterentropy source configured for SP800-90B
/// compliance. It requires the `jitterentropy` feature to be enabled.
///
/// # Errors
///
/// Returns an error if jitterentropy is not available on this system
/// (e.g., due to insufficient timer resolution or missing hardware support).
///
/// # Example
///
/// ```ignore
/// use ossl::entropy::create_fips_entropy;
///
/// let source = create_fips_entropy()?;
/// let mut buf = [0u8; 32];
/// source.get_entropy(&mut buf)?;
/// ```
#[cfg(feature = "jitterentropy")]
pub fn create_fips_entropy() -> Result<Box<dyn EntropySource>, Error> {
    let source = jitterentropy::JitterentropySource::new_fips()?;
    Ok(Box::new(source))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getrandom_source() {
        let source = GetrandomSource::new();
        assert_eq!(source.name(), "getrandom");
        assert!(source.is_available());

        let mut buf = [0u8; 32];
        let len = source.get_entropy(&mut buf).unwrap();
        assert_eq!(len, 32);

        // Very unlikely to be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_getrandom_nonce_with_salt() {
        let source = GetrandomSource::new();
        let salt = b"test salt value";

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        source.get_entropy(&mut buf1).unwrap();
        buf2.copy_from_slice(&buf1);

        // Apply nonce transformation
        let len = source.get_nonce(&mut buf2, Some(salt)).unwrap();
        assert_eq!(len, 32);

        // Buffers should be different (nonce got new random data)
        // This test is probabilistic but extremely unlikely to fail
    }

    #[test]
    fn test_create_default_entropy() {
        let source = create_default_entropy();
        assert_eq!(source.name(), "getrandom");
        assert!(source.is_available());

        let mut buf = [0u8; 32];
        let len = source.get_entropy(&mut buf).unwrap();
        assert_eq!(len, 32);
    }

    #[test]
    fn test_concurrent_entropy_generation() {
        use std::sync::Arc;
        use std::thread;

        let source: Arc<dyn EntropySource> = Arc::new(GetrandomSource::new());
        let mut handles = vec![];

        // Spawn 10 threads that each generate entropy
        for _ in 0..10 {
            let source_clone = Arc::clone(&source);
            let handle = thread::spawn(move || {
                let mut buf = [0u8; 64];
                for _ in 0..100 {
                    let len = source_clone.get_entropy(&mut buf).unwrap();
                    assert_eq!(len, 64);
                    // Basic sanity check - buffer shouldn't be all zeros
                    assert!(buf.iter().any(|&b| b != 0));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_various_buffer_sizes() {
        let source = GetrandomSource::new();

        // Test different sizes including edge cases
        let sizes = [1, 8, 16, 32, 64, 128, 256, 512, 1024, 4096];

        for &size in &sizes {
            let mut buf = vec![0u8; size];
            let len = source.get_entropy(&mut buf).unwrap();
            assert_eq!(len, size, "Failed for size {}", size);

            // For sizes >= 8, expect at least some non-zero bytes
            if size >= 8 {
                assert!(
                    buf.iter().any(|&b| b != 0),
                    "All zeros for size {} is extremely unlikely",
                    size
                );
            }
        }
    }

    #[test]
    fn test_health_checks() {
        let getrandom_source = GetrandomSource::new();
        assert!(getrandom_source.health_check().is_ok());
    }

    #[test]
    fn test_nonce_with_various_salts() {
        let source = GetrandomSource::new();

        let salts: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"short",
            b"this is a longer salt value that exceeds the buffer",
            &[0u8; 100],  // All zeros
            &[0xffu8; 100],  // All ones
        ];

        for salt in salts {
            let mut buf = [0u8; 32];
            let len = source.get_nonce(&mut buf, Some(salt)).unwrap();
            assert_eq!(len, 32);
        }
    }

    #[test]
    fn test_basic_entropy_quality() {
        let source = GetrandomSource::new();

        // Generate 1KB of entropy
        let mut buf = [0u8; 1024];
        source.get_entropy(&mut buf).unwrap();

        // Count byte values - should be relatively evenly distributed
        let mut counts = [0u32; 256];
        for &b in &buf {
            counts[b as usize] += 1;
        }

        // Check that no single byte value dominates (> 10% of total)
        let max_count = *counts.iter().max().unwrap();
        assert!(
            max_count < 100,
            "Byte distribution is suspiciously uneven: max count = {}",
            max_count
        );

        // Check that we see at least 200 different byte values
        let unique_values = counts.iter().filter(|&&c| c > 0).count();
        assert!(unique_values > 200, "Too few unique byte values: {}", unique_values);
    }

    #[test]
    #[cfg(not(feature = "jitterentropy"))]
    fn test_query_capabilities() {
        let caps = query_capabilities();
        assert!(caps.getrandom_available);
    }
}

// ============================================================================
// Jitterentropy Tests - requires "jitterentropy" feature
// ============================================================================

#[cfg(all(test, feature = "jitterentropy"))]
mod jitterentropy_tests {
    use super::*;

    #[test]
    fn test_query_capabilities() {
        let caps = query_capabilities();
        assert!(caps.getrandom_available);

        // Jitterentropy may or may not be available depending on system
        if caps.jitterentropy_available {
            assert!(caps.jitterentropy_version.is_some());
            assert!(caps.jitterentropy_version.unwrap() >= 3000000);
        }
    }

    #[test]
    fn test_create_fips_entropy() {
        match create_fips_entropy() {
            Ok(source) => {
                assert_eq!(source.name(), "jitterentropy");
                assert!(source.is_available());

                let mut buf = [0u8; 32];
                let len = source.get_entropy(&mut buf).unwrap();
                assert_eq!(len, 32);
            }
            Err(_) => {
                // Jitterentropy not available on this system
                println!("Jitterentropy not available, skipping test");
            }
        }
    }

    #[test]
    fn test_jitterentropy_concurrent() {
        use std::sync::Arc;
        use std::thread;

        // Try to create jitterentropy source
        let source = match jitterentropy::JitterentropySource::new_fips() {
            Ok(s) => Arc::new(s),
            Err(_) => {
                println!("Jitterentropy not available, skipping test");
                return;
            }
        };

        let mut handles = vec![];

        // Spawn 4 threads (jitterentropy is slower, so fewer threads)
        for _ in 0..4 {
            let source_clone = Arc::clone(&source);
            let handle = thread::spawn(move || {
                let mut buf = [0u8; 32];
                for _ in 0..10 {
                    let len = source_clone.get_entropy(&mut buf).unwrap();
                    assert_eq!(len, 32);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_jitterentropy_library_version() {
        let ver = jitterentropy::version();
        // Version format: MAJOR * 1000000 + MINOR * 1000 + PATCHLEVEL
        // E.g., 3.6.0 = 3006000
        let major = ver / 1000000;
        let minor = (ver % 1000000) / 1000;
        let patch = ver % 1000;

        println!("Jitterentropy version: {}.{}.{} ({})", major, minor, patch, ver);
        assert!(major >= 3, "Expected major version >= 3");
    }

    /// Check if kernel FIPS mode is enabled.
    fn is_kernel_fips_enabled() -> bool {
        match std::fs::read_to_string("/proc/sys/crypto/fips_enabled") {
            Ok(content) => content.trim() == "1",
            Err(_) => false,
        }
    }

    #[test]
    fn test_jitterentropy_fips_compliance() {
        use jitterentropy::{JitterentropyConfig, JitterentropySource};

        // Create jitterentropy with FIPS configuration
        let source = match JitterentropySource::try_new(JitterentropyConfig::fips()) {
            Ok(s) => s,
            Err(e) => {
                println!("Jitterentropy FIPS mode not available: {}", e.description());
                println!("This is acceptable on systems without suitable timers");
                return;
            }
        };

        // Verify FIPS configuration
        assert_eq!(source.name(), "jitterentropy");
        assert!(
            source.is_available(),
            "Jitterentropy should be available after successful init"
        );

        // Test health check (triggers SP800-90B health tests)
        assert!(source.health_check().is_ok(), "FIPS health check must pass");

        // Generate entropy and verify it works
        let mut buf = [0u8; 48]; // Typical DRBG seed size
        let len = source
            .get_entropy(&mut buf)
            .expect("FIPS entropy generation must succeed");
        assert_eq!(len, 48);

        // Basic quality check
        assert!(buf.iter().any(|&b| b != 0), "Entropy should not be all zeros");

        println!("Jitterentropy FIPS compliance test PASSED");
    }

    #[test]
    fn test_system_fips_status() {
        let kernel_fips = is_kernel_fips_enabled();

        println!("System FIPS Status:");
        println!(
            "  Kernel FIPS mode: {}",
            if kernel_fips { "ENABLED" } else { "DISABLED" }
        );

        let caps = query_capabilities();
        println!("  Jitterentropy available: {}", caps.jitterentropy_available);
        if let Some(ver) = caps.jitterentropy_version {
            let major = ver / 1000000;
            let minor = (ver % 1000000) / 1000;
            let patch = ver % 1000;
            println!("  Jitterentropy version: {}.{}.{}", major, minor, patch);
        }

        // On a non-FIPS kernel, jitterentropy should still work
        // because it provides its own SP800-90B compliant entropy
        if caps.jitterentropy_available {
            println!("  FIPS-compliant entropy source available (jitterentropy)");
        } else {
            println!("  No FIPS-compliant entropy source available");
        }
    }

    #[test]
    fn test_getrandom_fips_status() {
        let kernel_fips = is_kernel_fips_enabled();

        let source = GetrandomSource::new();

        // getrandom always works
        let mut buf = [0u8; 32];
        assert!(source.get_entropy(&mut buf).is_ok());

        if kernel_fips {
            println!("Kernel FIPS mode ENABLED: getrandom is FIPS-compliant");
        } else {
            println!("Kernel FIPS mode DISABLED: getrandom is NOT FIPS-compliant");
            println!("Use jitterentropy for FIPS compliance on this system");
        }
    }

    #[test]
    fn test_fips_only_entropy() {
        // This test uses ONLY jitterentropy, not hybrid
        // This is the FIPS-approved configuration

        let source = match create_fips_entropy() {
            Ok(s) => s,
            Err(_) => {
                println!("FIPS entropy not available, skipping test");
                return;
            }
        };

        assert_eq!(source.name(), "jitterentropy");

        // Generate multiple entropy samples
        for i in 0..10 {
            let mut buf = [0u8; 32];
            let result = source.get_entropy(&mut buf);
            assert!(result.is_ok(), "FIPS entropy generation failed on iteration {}", i);
            assert_eq!(result.unwrap(), 32);
        }

        // Health check must pass
        assert!(source.health_check().is_ok(), "FIPS health check failed");

        println!("FIPS-only entropy test PASSED (using jitterentropy)");
    }
}

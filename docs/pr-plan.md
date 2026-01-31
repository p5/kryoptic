# Jitterentropy Integration PR Plan

This document outlines a series of pull requests to add jitterentropy entropy source support to Kryoptic. The PRs are ordered by dependency.

## Overview

| PR # | Title | Lines | Complexity | Independently Testable |
| ---- | ----- | ----- | ---------- | ---------------------- |
| 1 | Core entropy abstraction | ~320 | Low | Yes |
| 2 | Jitterentropy + build system + FIPS integration | ~1,650 | High | Yes |
| 3 | Documentation | ~1,350 | Low | N/A |

Total: ~3,320 lines across 3 PRs

---

## Revision Notes

The original plan proposed 4 PRs, but analysis revealed that the original PR 3 (FIPS + config integration) had problematic dependencies:

1. **fips.rs changes depend on BOTH the core abstraction AND jitterentropy** - Functions like `use_jitterentropy_entropy()` and `use_fips_compliant_entropy()` require the jitterentropy module to exist.

2. **The FIPS integration is what makes the abstraction useful** - Without wiring up the entropy source to `fips_get_entropy`, the abstraction layer does nothing. This creates an awkward intermediate state.

3. **Config changes only work with FIPS changes** - `EntropySourceConfig::apply()` calls functions defined in fips.rs.

**Recommendation implemented:** Merge original PR 2 and PR 3 into a single PR. This keeps all jitterentropy-related functionality together and avoids artificial separation of tightly coupled code.

---

## PR 1: Core Entropy Abstraction

**Branch name:** `feature/entropy-abstraction`

**Description:**
Introduce the `EntropySource` trait and `GetrandomSource` implementation. This provides the foundation for pluggable entropy sources without adding any new dependencies or features.

**Files:**

```text
ossl/src/entropy/mod.rs (new, partial)  ~320 lines
ossl/src/lib.rs                         +1 line
```

**What's included:**

- `EntropySource` trait with `get_entropy()`, `get_nonce()`, `health_check()`, `is_available()`
- `GetrandomSource` - wraps the `getrandom` crate
- `create_default_entropy()` convenience function
- `EntropyCapabilities` struct (non-jitterentropy version)
- `query_capabilities()` function (non-jitterentropy version)
- Core unit tests (9 tests, no jitterentropy dependency)

**What's NOT included (deferred to PR 2):**

- `jitterentropy` module and feature gate
- `create_fips_entropy()` function
- Jitterentropy-specific fields in `EntropyCapabilities`
- All jitterentropy-related tests
- FIPS provider integration
- Configuration system

**File structure after PR 1:**

```rust
// ossl/src/entropy/mod.rs

// Lines 1-157: Core trait + GetrandomSource + create_default_entropy()
// Lines 192-240: EntropyCapabilities + query_capabilities() (non-jitterentropy)
// Lines 243-398: Core tests
// Lines 606-619: Non-jitterentropy query_capabilities test
```

**Testing:**

```bash
cargo test -p ossl --features dynamic -- entropy

# Expected: 9 tests passing
# - test_getrandom_source
# - test_getrandom_nonce_with_salt
# - test_create_default_entropy
# - test_concurrent_entropy_generation
# - test_various_buffer_sizes
# - test_health_checks
# - test_nonce_with_various_salts
# - test_basic_entropy_quality
# - test_query_capabilities_without_jitterentropy
```

**Review focus:**

- Thread safety (`Send + Sync` requirements)
- Trait design (extensibility for future entropy sources)
- Memory handling in nonce generation

**Commit message:**

```text
feat(ossl): add pluggable entropy source abstraction

Introduce EntropySource trait and GetrandomSource implementation to
support pluggable entropy providers. This lays the foundation for
adding FIPS-compliant entropy sources like jitterentropy.

- Add EntropySource trait with get_entropy, get_nonce, health_check
- Implement GetrandomSource wrapping the getrandom crate
- Add create_default_entropy() convenience function
- Add comprehensive unit tests
```

---

## PR 2: Jitterentropy + Build System + FIPS Integration

**Branch name:** `feature/jitterentropy-integration`

**Dependencies:** PR 1

**Description:**
Add jitterentropy FFI bindings, the `JitterentropySource` implementation, build system support, FIPS provider integration, and configuration system. This PR adds the `jitterentropy` feature flag and wires everything together.

**Rationale for combining original PR 2 and PR 3:**
The FIPS integration code (`use_jitterentropy_entropy()`, `use_fips_compliant_entropy()`) directly depends on the jitterentropy module. Splitting them would require:
- Stub implementations or compile errors in the intermediate state
- Reviewers to understand an incomplete system
- Extra work to ensure each PR compiles independently

By combining them, reviewers see the complete jitterentropy feature in one coherent PR.

**Files:**

```text
ossl/src/entropy/jitterentropy.rs (new)  ~707 lines
ossl/src/entropy/mod.rs (additions)      ~300 lines
ossl/build.rs                            ~158 lines added
ossl/Cargo.toml                          +2 lines
Cargo.toml                               +3 lines
ossl/src/fips.rs                         ~300 lines added/changed
src/config.rs                            ~240 lines added
src/lib.rs                               ~18 lines added
```

**What's included:**

1. **FFI bindings** (`entropy/jitterentropy.rs`)
   - FFI declarations for libjitterentropy C library
   - `JitterentropyError` enum with detailed error types
   - `JitterentropyConfig` for FIPS/resilient modes
   - `JitterentropySource` with thread-local collectors
   - `OnceLock`-based initialization
   - Always enforces `JENT_FORCE_FIPS` flag for SP800-90B compliance
   - Buffer zeroization on all error paths
   - Automatic collector recovery from permanent health test failures

2. **Additions to mod.rs** (lines 158-242, 399-605)
   - Feature gate for jitterentropy module
   - `create_fips_entropy()` function
   - `EntropyCapabilities` struct with jitterentropy fields
   - `query_capabilities()` function (jitterentropy version)
   - Jitterentropy integration tests (~14 tests)

3. **Build system** (`build.rs`)
   - Dynamic builds: link to system `libjitterentropy.so`
   - FIPS builds: compile from source with `-O0` optimization
   - Critical flags: `-fno-strict-aliasing`, `-fno-omit-frame-pointer`

4. **FIPS integration** (`fips.rs`)
   - Global `ENTROPY_SOURCE: LazyLock<RwLock<Box<dyn EntropySource>>>`
   - `set_entropy_source()` - panics on lock poisoning (fail closed)
   - `entropy_source_name()` - get current source name
   - `use_getrandom_entropy()` - configure getrandom
   - `use_jitterentropy_entropy()` - configure jitterentropy
   - `use_fips_compliant_entropy()` - auto-detect based on kernel FIPS mode
   - `is_kernel_fips_mode()` - check `/proc/sys/crypto/fips_enabled`
   - `get_entropy_internal()` - routes through configured source
   - Integration with OpenSSL callbacks (`fips_get_entropy`, `fips_get_nonce`)

5. **Configuration** (`config.rs`)
   - `EntropySourceConfig` enum: `Auto`, `Getrandom`, `Jitterentropy`
   - `entropy_source` field in `Config` struct
   - `EntropySourceConfig::apply()` method

6. **Initialization** (`lib.rs`)
   - Apply entropy configuration in `fn_initialize()` before `ossl::fips::init()`

**Configuration example:**

```toml
# Entropy source configuration (FIPS builds only)
# Options: "auto" (default), "getrandom", "jitterentropy"
entropy_source = "auto"

[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/var/lib/kryoptic/token.sql"
```

**Entropy Source Options:**

| Value | Behavior |
| ----- | -------- |
| `auto` | Uses `getrandom` on FIPS kernels, `jitterentropy` on non-FIPS kernels |
| `getrandom` | Always use kernel's `getrandom()` syscall |
| `jitterentropy` | Always use jitterentropy (requires feature) |

**Testing:**

```bash
# Dynamic build
cargo build --features "dynamic,jitterentropy"

# Run all tests
cargo test --features "dynamic,jitterentropy"

# Expected: ~134 tests passing

# Entropy-specific tests
cargo test -p ossl --features "dynamic,jitterentropy" -- entropy

# Expected: 27 tests passing (9 core + 18 jitterentropy)

# FIPS build (requires sources)
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl
export KRYOPTIC_JITTERENTROPY_SOURCES=/path/to/jitterentropy-library
cargo build --no-default-features --features "standard,fips,jitterentropy"

# Config tests
cargo test --no-default-features --features "standard,fips,jitterentropy" -- entropy_config

# Expected: 7 config tests passing
```

**Review focus:**

- FFI safety (null checks, error handling)
- Thread-local storage pattern for collectors
- FIPS flag enforcement (`JENT_FORCE_FIPS` always set)
- Buffer zeroization on error paths
- Build system flags (critical `-O0` for entropy quality)
- Lock handling (panic on poison for FIPS safety)
- Collector recovery from permanent failures
- OpenSSL callback integration (no behavioral changes to existing code paths)
- Configuration parsing and validation
- Initialization ordering (entropy before FIPS init)
- Test isolation with `#[serial]`

**Commit message:**

```text
feat(fips): add jitterentropy entropy source for FIPS compliance

Integrate jitterentropy as an SP800-90B compliant entropy source for
FIPS 140-3 certification. This provides a user-space entropy source
that works on systems without kernel FIPS mode.

Key features:
- Pluggable EntropySource trait with GetrandomSource
- JitterentropySource with thread-local collectors and FIPS enforcement
- Dynamic builds link to system libjitterentropy.so
- FIPS builds compile jitterentropy from source with -O0
- Configuration via TOML file or KRYOPTIC_ENTROPY_SOURCE env var
- Auto-detection of kernel FIPS mode for source selection

Security:
- Buffer zeroization on all error paths
- Lock poisoning causes panic (fail closed)
- JENT_FORCE_FIPS always applied for SP800-90B compliance
- Automatic recovery from permanent health test failures

Build:
- Dynamic: cargo build --features "dynamic,jitterentropy"
- FIPS: cargo build --no-default-features --features "standard,fips,jitterentropy"
```

---

## PR 3: Documentation

**Branch name:** `docs/jitterentropy`

**Dependencies:** PRs 1-2 (can be reviewed in parallel)

**Description:**
Add comprehensive documentation for the jitterentropy integration and build system.

**Files:**

```text
docs/jitterentropy.md               ~400 lines (user guide)
docs/jitterentropy-implementation.md ~550 lines (developer guide)
docs/build-configurations.md        ~310 lines (build options)
Containerfile                       ~82 lines (build environment)
```

**Contents:**

1. **jitterentropy.md** - User guide
   - Why jitterentropy is needed for FIPS
   - How CPU timing jitter works
   - Build modes (dynamic vs FIPS)
   - Configuration options
   - Troubleshooting common issues

2. **jitterentropy-implementation.md** - Developer guide
   - Architecture overview with diagrams
   - FFI bindings implementation details
   - Thread safety model
   - Build system details
   - Testing guide

3. **build-configurations.md** - Build options reference
   - Dynamic vs FIPS modes explained
   - Feature flags reference
   - Environment variables
   - Build commands for each configuration

4. **Containerfile** - Build environment
   - Fedora-based container with all dependencies
   - Supports both dynamic and FIPS builds

**Review focus:**

- Technical accuracy
- Completeness of configuration options
- Code examples match actual API

**Commit message:**

```text
docs: add jitterentropy integration documentation

Add comprehensive documentation for jitterentropy entropy source
integration, including user guide, developer guide, and build
configuration reference.

- docs/jitterentropy.md: User guide with FIPS configuration
- docs/jitterentropy-implementation.md: Developer/architecture guide
- docs/build-configurations.md: Build options reference
- Containerfile: Fedora build environment with all dependencies
```

---

## Summary: File to PR Mapping

| File | PR | Lines |
| ---- | --- | ----- |
| `ossl/src/entropy/mod.rs` (core) | 1 | ~320 |
| `ossl/src/lib.rs` (+1 line) | 1 | 1 |
| `ossl/src/entropy/jitterentropy.rs` | 2 | ~707 |
| `ossl/src/entropy/mod.rs` (jitterentropy parts) | 2 | ~300 |
| `ossl/build.rs` | 2 | ~158 |
| `ossl/Cargo.toml` | 2 | 2 |
| `Cargo.toml` | 2 | 3 |
| `ossl/src/fips.rs` | 2 | ~300 |
| `src/config.rs` | 2 | ~240 |
| `src/lib.rs` | 2 | ~18 |
| `docs/jitterentropy.md` | 3 | ~400 |
| `docs/jitterentropy-implementation.md` | 3 | ~550 |
| `docs/build-configurations.md` | 3 | ~310 |
| `Containerfile` | 3 | ~82 |
| `docs/pr-plan.md` | 3 | ~300 |

---

## Dependency Graph

```
PR 1: Core Entropy Abstraction
  │
  │  Provides: EntropySource trait, GetrandomSource
  │
  ▼
PR 2: Jitterentropy + FIPS Integration
  │
  │  Provides: JitterentropySource, FIPS wiring, config
  │  Requires: PR 1 (EntropySource trait)
  │
  ▼
PR 3: Documentation
     
     Can be reviewed in parallel with PR 1 and PR 2
     Should be merged after PR 2
```

---

## Review Checklist

For each PR, reviewers should verify:

- [ ] Code compiles with and without `jitterentropy` feature
- [ ] All tests pass
- [ ] No new warnings
- [ ] Memory handling is correct (zeroization on error paths)
- [ ] Thread safety is maintained
- [ ] FIPS requirements are met (fail closed, not open)
- [ ] No behavioral changes to existing code paths (getrandom-only builds)
- [ ] Documentation is accurate
- [ ] Commit messages follow project conventions

---

## Alternative: 4-PR Split

If reviewers prefer smaller PRs, the original 4-PR plan can still be used with the following modification to PR 3:

**PR 3a: Core FIPS Integration** (depends on PR 1 only)
- `ENTROPY_SOURCE` global with RwLock
- `set_entropy_source()`, `entropy_source_name()`
- `use_getrandom_entropy()`
- `get_entropy_internal()` wiring
- No jitterentropy-specific code

**PR 3b: Jitterentropy FIPS + Config** (depends on PR 2 and PR 3a)
- `use_jitterentropy_entropy()`
- `use_fips_compliant_entropy()`
- `is_kernel_fips_mode()`
- `EntropySourceConfig` and config.rs changes
- Initialization hook in lib.rs

This adds complexity but keeps each PR smaller. The recommended 3-PR split above is simpler.

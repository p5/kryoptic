// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::panic::set_hook;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct OsslCallbacks;
const OPENSSL_3_0_7: i64 = 0x30000070;
const OPENSSL_3_2_0: i64 = 0x30200000;
const OPENSSL_3_5_0: i64 = 0x30500000;
const OPENSSL_4_0_0: i64 = 0x40000000;

impl bindgen::callbacks::ParseCallbacks for OsslCallbacks {
    fn int_macro(
        &self,
        name: &str,
        value: i64,
    ) -> Option<bindgen::callbacks::IntKind> {
        if name == "OPENSSL_VERSION_NUMBER" {
            if value < OPENSSL_4_0_0 {
                #[cfg(feature = "ossl400")]
                panic!("OpenSSL 4.0.0 or later is required");
            }
            if value < OPENSSL_3_5_0 {
                #[cfg(feature = "ossl350")]
                panic!("OpenSSL 3.5.0 or later is required");
            }
            if value < OPENSSL_3_2_0 {
                #[cfg(feature = "ossl320")]
                panic!("OpenSSL 3.2.0 or later is required");
            }
            if value < OPENSSL_3_0_7 {
                panic!(
                    "OpenSSL 3.0.7 is the minimum viable version. Found {:x}",
                    value
                );
            }
            /* Emit versions we found, versions stack, so code
             * just need to build conditionalized just to the older version
             * that introduced the desired feature */
            println!("cargo::rustc-cfg=ossl_v307");
            if value >= OPENSSL_3_2_0 {
                println!("cargo::rustc-cfg=ossl_v320");
            }
            if value >= OPENSSL_3_5_0 {
                println!("cargo::rustc-cfg=ossl_v350");
            }
            if value >= OPENSSL_4_0_0 {
                println!("cargo::rustc-cfg=ossl_v400");
            }
        }

        None
    }

    fn str_macro(&self, name: &str, _value: &[u8]) {
        if name == "OSSL_PKEY_PARAM_SLH_DSA_SEED" {
            println!("cargo::rustc-cfg=ossl_slhdsa")
        }
        if name == "OSSL_PKEY_PARAM_ML_DSA_SEED" {
            println!("cargo::rustc-cfg=ossl_mldsa")
        }
        if name == "OSSL_PKEY_PARAM_ML_KEM_SEED" {
            println!("cargo::rustc-cfg=ossl_mlkem")
        }
    }

    fn func_macro(&self, name: &str, _value: &[&[u8]]) {
        if name == "OSSL_PARAM_clear_free" {
            println!("cargo::rustc-cfg=param_clear_free")
        }
    }
}

fn ossl_bindings(args: &mut Vec<String>, out_file: &Path) {
    if let Some(var) = env::var("OSSL_BINDGEN_CLANG_ARGS").ok() {
        for arg in var.split_whitespace() {
            args.push(arg.to_string());
        }
    }

    bindgen::Builder::default()
        .header("ossl.h")
        .clang_args(args)
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .allowlist_item("ossl_.*")
        .allowlist_item("OSSL_.*")
        .allowlist_item("openssl_.*")
        .allowlist_item("OPENSSL_.*")
        .allowlist_item("CRYPTO_.*")
        .allowlist_item("c_.*")
        .allowlist_item("EVP_.*")
        .allowlist_item("evp_.*")
        .allowlist_item("BN_.*")
        .allowlist_item("LN_aes.*")
        .allowlist_item("ERR.*")
        .allowlist_item("BIO.*")
        .blocklist_item("evp_pkey_ctx_st__.*")
        .opaque_type("ecx_key_st")
        .opaque_type("evp_pkey_ctx_st")
        .parse_callbacks(Box::new(OsslCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
}

fn build_ossl(out_file: &Path) {
    let sources = std::env::var("KRYOPTIC_OPENSSL_SOURCES")
        .expect("Env var KRYOPTIC_OPENSSL_SOURCES is not defined");
    let openssl_path = std::path::PathBuf::from(sources)
        .canonicalize()
        .expect("cannot canonicalize OpenSSL path");

    let mut buildargs = vec![
        "no-deprecated",
        "no-aria",
        "no-argon2",
        "no-atexit",
        "no-des",
        "no-dsa",
        "no-cast",
        "no-mdc2",
        "no-ec2m",
        "no-rc2",
        "no-rc4",
        "no-rc5",
        "no-rmd160",
        "no-seed",
        "no-sm2",
        "no-sm3",
        "no-sm4",
    ];

    match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => match arch.as_str() {
            "x86" => {
                buildargs.insert(0, "linux-elf");
                buildargs.push("-m32");
                buildargs.push("-latomic");
            }
            "x86_64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "aarch64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "powerpc64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "s390x" => buildargs.push("no-ec_nistp_64_gcc_128"),
            _ => (),
        },
        _ => panic!("No arch available in CARGO_CFG_TARGET_ARCH"),
    }

    if env::var("PROFILE").unwrap().as_str() == "debug" {
        buildargs.push("--debug");
    }

    let mut defines = "-DDEVRANDOM=\\\"/dev/urandom\\\"".to_string();

    let ar_path: std::path::PathBuf;
    let ar_name: &str;

    if cfg!(feature = "fips") {
        buildargs.push("enable-fips");

        defines.push_str(" -DOPENSSL_PEDANTIC_ZEROIZATION");

        let fips_name = match std::env::var("KRYOPTIC_FIPS_VENDOR") {
            Ok(name) => name,
            Err(_) => env!("CARGO_PKG_NAME").to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_VENDOR=\\\"{}\\\"",
            fips_name,
        ));

        let fips_ver = match std::env::var("KRYOPTIC_FIPS_VERSION") {
            Ok(ver) => ver,
            Err(_) => env!("CARGO_PKG_VERSION").to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_VERSION=\\\"{}\\\"",
            fips_ver,
        ));

        let fips_build = match std::env::var("KRYOPTIC_FIPS_BUILD") {
            Ok(bd) => bd,
            Err(_) => "test".to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_BUILD=\\\"{}\\\"",
            fips_build,
        ));

        ar_name = "fips";
        ar_path = openssl_path
            .join("providers")
            .canonicalize()
            .expect("OpenSSL providers path unavailable");
    } else {
        ar_path = openssl_path.clone();
        ar_name = "crypto";
    }

    buildargs.push(&defines);

    let libpath = format!("{}/lib{}.a", ar_path.to_string_lossy(), ar_name);

    println!("cargo:rustc-link-search={}", ar_path.to_string_lossy());
    println!("cargo:rustc-link-lib=static={}", ar_name);
    println!("cargo:rerun-if-changed={}", libpath);

    /* must declare this after the static one or builds will fail */
    match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => match arch.as_str() {
            "x86" => {
                println!("cargo::rustc-link-lib=atomic");
            }
            _ => (),
        },
        _ => panic!("No arch available in CARGO_CFG_TARGET_ARCH"),
    }

    match std::path::Path::new(&libpath).try_exists() {
        Ok(true) => (),
        _ => {
            /* openssl: ./Configure --debug enable-fips */
            if !std::process::Command::new("./Configure")
                .current_dir(&openssl_path)
                .args(buildargs)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `Configure`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not configure OpenSSL");
            }

            if !std::process::Command::new("make")
                .current_dir(&openssl_path)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `make`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not build OpenSSL");
            }
        }
    }

    let include_path = format!(
        "-I{}",
        openssl_path
            .join("include")
            .canonicalize()
            .expect("OpenSSL include path unavailable")
            .to_str()
            .unwrap()
    );

    let mut args: Vec<String> = Vec::new();
    args.push(include_path);
    if cfg!(feature = "fips") {
        args.push("-D_KRYOPTIC_FIPS_".to_string());
    }

    ossl_bindings(&mut args, out_file);
}

fn use_system_ossl(out_file: &Path) {
    let library = pkg_config::Config::new()
        .atleast_version("3.0.7")
        .probe("openssl")
        .unwrap();

    let mut args: Vec<String> = Vec::new();
    for include_path in library.include_paths {
        args.push(["-I", include_path.to_str().unwrap()].concat());
    }

    ossl_bindings(&mut args, out_file);
}

/// Use the system-installed jitterentropy library (for dynamic builds).
///
/// Links to libjitterentropy.so from the system package.
#[cfg(feature = "jitterentropy")]
fn use_system_jitterentropy() {
    // Try to find the system library
    // jitterentropy doesn't provide pkg-config, so we check directly
    let lib_paths = [
        "/usr/lib64",
        "/usr/lib",
        "/usr/local/lib64",
        "/usr/local/lib",
    ];

    let header_paths = [
        "/usr/include",
        "/usr/local/include",
    ];

    let mut lib_found = false;
    let mut header_found = false;

    for path in &lib_paths {
        let lib_path = std::path::Path::new(path).join("libjitterentropy.so");
        if lib_path.exists() {
            println!("cargo:rustc-link-search=native={}", path);
            lib_found = true;
            break;
        }
    }

    for path in &header_paths {
        let header_path = std::path::Path::new(path).join("jitterentropy.h");
        if header_path.exists() {
            header_found = true;
            break;
        }
    }

    if !lib_found {
        panic!(
            "System jitterentropy library not found. \
             Install the jitterentropy-devel package or use FIPS mode \
             to compile from source."
        );
    }

    if !header_found {
        panic!(
            "System jitterentropy headers not found. \
             Install the jitterentropy-devel package."
        );
    }

    // Link dynamically to the system library
    println!("cargo:rustc-link-lib=jitterentropy");

    // pthread is still needed for the internal timer
    println!("cargo:rustc-link-lib=pthread");
}

/// Build the jitterentropy library from source (for FIPS builds).
///
/// IMPORTANT: Jitterentropy MUST be compiled with -O0 (no optimization)
/// to preserve the timing jitter that provides entropy.
#[cfg(feature = "jitterentropy")]
fn build_jitterentropy_from_source() {
    // Jitterentropy sources must be provided via environment variable,
    // consistent with how OpenSSL sources are handled for FIPS builds.
    let jent_path = std::env::var("KRYOPTIC_JITTERENTROPY_SOURCES")
        .map(std::path::PathBuf::from)
        .expect(
            "Env var KRYOPTIC_JITTERENTROPY_SOURCES is not defined. \
             Set it to the path of the jitterentropy-library source directory. \
             Example: export KRYOPTIC_JITTERENTROPY_SOURCES=/path/to/jitterentropy-library"
        );

    if !jent_path.exists() {
        panic!(
            "Jitterentropy sources not found at {:?}. \
             Verify KRYOPTIC_JITTERENTROPY_SOURCES points to a valid directory.",
            jent_path
        );
    }

    let jent_path = jent_path
        .canonicalize()
        .expect("Cannot canonicalize jitterentropy path");

    println!("cargo:rerun-if-changed={}", jent_path.display());

    // Source files for jitterentropy library
    let source_files = [
        "src/jitterentropy-base.c",
        "src/jitterentropy-gcd.c",
        "src/jitterentropy-health.c",
        "src/jitterentropy-noise.c",
        "src/jitterentropy-sha3.c",
        "src/jitterentropy-timer.c",
    ];

    // CRITICAL: Remove ALL C/C++ build flags from the environment.
    // Jitterentropy's entropy quality depends on precise timing characteristics
    // that can be destroyed by optimization flags (e.g., -O2, -O3) that may be
    // present in environment variables set by the caller (e.g., RPM %{optflags}).
    // We must have complete control over the compilation flags.
    //
    // Save and remove these environment variables to prevent the cc crate
    // from inheriting any flags that could affect optimization.
    let env_vars_to_clear = [
        // Standard C/C++ flags
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        // RPM-specific variables
        "RPM_OPT_FLAGS",
        "RPM_LD_FLAGS",
        "RPM_BUILD_ROOT",
        // Cargo/cc crate variables
        "DEBUG",
        "OPT_LEVEL",
        "TARGET_CFLAGS",
        "TARGET_CXXFLAGS",
        "TARGET_CPPFLAGS",
        "HOST_CFLAGS",
        "HOST_CXXFLAGS",
        "HOST_CPPFLAGS",
        // Architecture-specific variants (cc crate checks these)
        "CFLAGS_x86_64-unknown-linux-gnu",
        "CFLAGS_x86_64_unknown_linux_gnu",
        "CFLAGS_aarch64-unknown-linux-gnu",
        "CFLAGS_aarch64_unknown_linux_gnu",
        // Generic target variables
        "CC_FLAGS",
        "CXX_FLAGS",
    ];
    
    // Also clear any target-specific CFLAGS that cc might pick up
    let target = env::var("TARGET").unwrap_or_default();
    let target_underscore = target.replace('-', "_");
    let target_specific_vars = [
        format!("CFLAGS_{}", target),
        format!("CFLAGS_{}", target_underscore),
        format!("CXXFLAGS_{}", target),
        format!("CXXFLAGS_{}", target_underscore),
        format!("CPPFLAGS_{}", target),
        format!("CPPFLAGS_{}", target_underscore),
    ];
    
    // Save all env vars before clearing
    let mut saved_env: Vec<(String, Option<String>)> = env_vars_to_clear
        .iter()
        .map(|var| (var.to_string(), env::var(var).ok()))
        .collect();
    
    for var in &target_specific_vars {
        saved_env.push((var.clone(), env::var(var).ok()));
    }
    
    // Clear all the variables
    // SAFETY: We are in a build script which is single-threaded at this point,
    // and we restore the variables after the jitterentropy build completes.
    for var in &env_vars_to_clear {
        unsafe { env::remove_var(var) };
    }
    for var in &target_specific_vars {
        unsafe { env::remove_var(var) };
    }
    
    let mut build = cc::Build::new();

    // Disable cargo's automatic debug and optimization settings
    // so we have full control over the flags
    build.debug(false);
    build.opt_level(0);
    
    // Add source files
    for src in &source_files {
        let src_path = jent_path.join(src);
        if !src_path.exists() {
            panic!("Jitterentropy source file not found: {:?}", src_path);
        }
        build.file(&src_path);
        println!("cargo:rerun-if-changed={}", src_path.display());
    }

    // Include paths
    build.include(&jent_path);
    build.include(jent_path.join("src"));

    // CRITICAL FOR FIPS: Compile with -O0 to preserve timing jitter.
    // The jitterentropy library's entropy quality depends on CPU timing
    // variations that compiler optimizations would eliminate.
    // Environment variables are cleared above to prevent any inherited
    // optimization flags from affecting the build.
    build.force_frame_pointer(true);

    // Enable internal timer support for systems without high-res timers
    build.define("JENT_CONF_ENABLE_INTERNAL_TIMER", None);

    // Build as a static library
    build.compile("jitterentropy");

    // Restore the saved environment variables
    // SAFETY: We are in a build script which is single-threaded at this point.
    for (var, value) in saved_env {
        if let Some(v) = value {
            unsafe { env::set_var(&var, v) };
        }
    }

    // Link pthread for internal timer support
    println!("cargo:rustc-link-lib=pthread");
}

fn set_pretty_panic() {
    set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            if s != &"panic in a function that cannot unwind" {
                println!("Compile Error: {s:?}");
            }
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            if s != "panic in a function that cannot unwind" {
                println!("Compile Error: {s:?}");
            }
        } else {
            if let Some(location) = panic_info.location() {
                println!(
                    "Unrecognized compile error in file '{}' at line {}",
                    location.file(),
                    location.line(),
                );
            } else {
                println!("Unknown panic with no location information...");
            }
        }
    }));
}

fn main() {
    set_pretty_panic();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ossl_bindings = out_path.join("ossl_bindings.rs");

    /* Always emit known configs */
    println!("cargo::rustc-check-cfg=cfg(ossl_v307,ossl_v320,ossl_v350,ossl_v400,ossl_mldsa,ossl_mlkem,ossl_slhdsa,param_clear_free)");

    /* OpenSSL Cryptography */
    if cfg!(feature = "dynamic") {
        use_system_ossl(&ossl_bindings);
    } else {
        build_ossl(&ossl_bindings);
    }

    /* Jitterentropy library */
    #[cfg(feature = "jitterentropy")]
    {
        if cfg!(feature = "dynamic") {
            // Dynamic builds: link to system libjitterentropy.so
            use_system_jitterentropy();
        } else {
            // FIPS builds: compile from source for reproducibility
            build_jitterentropy_from_source();
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}

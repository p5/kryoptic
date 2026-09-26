// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::path::PathBuf;

const JENT_FUNCTIONS: [&str; 6] = [
    "jent_entropy_collector_alloc",
    "jent_entropy_collector_free",
    "jent_entropy_init_ex",
    "jent_read_entropy_safe",
    "jent_status",
    "jent_version",
];

pub fn build() {
    let lib_dir = env::var_os("KRYOPTIC_JITTERENTROPY_LIB_DIR")
        .map(PathBuf::from)
        .expect(
            "set KRYOPTIC_JITTERENTROPY_LIB_DIR to the JENT library directory",
        )
        .canonicalize()
        .expect("cannot resolve the JENT library directory");
    let include_dir = env::var_os("KRYOPTIC_JITTERENTROPY_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| lib_dir.clone())
        .canonicalize()
        .expect("cannot resolve the JENT include directory");

    let header = include_dir.join("jitterentropy.h");
    assert!(header.is_file(), "JENT package has no jitterentropy.h");
    let header_file =
        header.canonicalize().expect("cannot resolve JENT header");
    let linker_name = lib_dir.join("libjitterentropy.so");
    assert!(
        linker_name.is_file(),
        "JENT package has no libjitterentropy.so linker name"
    );
    let library = linker_name
        .canonicalize()
        .expect("cannot resolve JENT shared library");
    assert_eq!(
        library.parent(),
        Some(lib_dir.as_path()),
        "JENT linker name must select a library inside the package directory"
    );

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"),
    );
    let target = env::var("TARGET").expect("Cargo did not set TARGET");
    let mut bindings = bindgen::Builder::default()
        .header(header_file.to_string_lossy())
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg(format!("--target={target}"))
        .formatter(bindgen::Formatter::Prettyplease)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("^rand_data$")
        .allowlist_var(
            "^JENT_(DISABLE_INTERNAL_TIMER|FORCE_FIPS|MAJVERSION|VERSION)$",
        );

    for function in JENT_FUNCTIONS {
        bindings = bindings.allowlist_function(format!("^{function}$"));
    }

    bindings
        .generate()
        .expect("cannot generate bindings from the JENT package header")
        .write_to_file(out_dir.join("jent_bindings.rs"))
        .expect("cannot write JENT bindings");

    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", header_file.display());
    println!("cargo:rerun-if-changed={}", linker_name.display());
    println!("cargo:rerun-if-changed={}", library.display());
    println!("cargo:rerun-if-env-changed=KRYOPTIC_JITTERENTROPY_LIB_DIR");
    println!("cargo:rerun-if-env-changed=KRYOPTIC_JITTERENTROPY_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");
    println!(
        "cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS_{}",
        target.replace('-', "_")
    );
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=jitterentropy");
}

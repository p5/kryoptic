// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use crate::fips::entropy::{jitter_successful_fills, ENTROPY_SOURCE};
use crate::tests::*;

#[test]
fn pkcs11_random_calls_use_the_jent_seeded_drbg() {
    assert_eq!(ENTROPY_SOURCE, "jitterentropy");

    let before_setup = jitter_successful_fills();
    let mut token = TestToken::initialized("test_jitterentropy_pkcs11", None);
    let session = token.get_session(true);
    token.login();
    assert!(jitter_successful_fills() > before_setup);
    crate::fips::entropy::enable_os_rng_denial_for_test();

    let mut output = [0; 64];
    let ret = fn_generate_random(
        session,
        output.as_mut_ptr(),
        output.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert!(output.iter().any(|byte| *byte != 0));
    let before_seed = jitter_successful_fills();
    let seed = b"caller supplied additional input";
    let ret = fn_seed_random(
        session,
        seed.as_ptr() as *mut CK_BYTE,
        seed.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let after_seed = jitter_successful_fills();
    assert!(after_seed > before_seed);

    let aes_key = generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_AES), (CKA_VALUE_LEN, 16)],
        &[],
        &[],
    )
    .expect("PKCS#11 symmetric key generation succeeds");
    assert_ne!(aes_key, CK_INVALID_HANDLE);

    let ec_params = asn1::write_single(&crate::kasn1::oid::EC_SECP256R1)
        .expect("P-256 parameters encode");
    let (ec_public_key, ec_private_key) = generate_key_pair(
        session,
        CKM_EC_KEY_PAIR_GEN,
        &[],
        &[(CKA_EC_PARAMS, &ec_params)],
        &[(CKA_TOKEN, false)],
        &[],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, false),
            (CKA_TOKEN, false),
            (CKA_EXTRACTABLE, true),
        ],
    )
    .expect("PKCS#11 EC key-pair generation succeeds");
    assert_ne!(ec_public_key, CK_INVALID_HANDLE);
    assert_ne!(ec_private_key, CK_INVALID_HANDLE);

    token.finalize();
}

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements interfaces needed to access a Random Number
//! Generator

use crate::error::Result;
use crate::mechanism;
use crate::ossl::drbg;

#[derive(Debug)]
pub struct RNG {
    drbg: Box<dyn mechanism::DRBG>,
}

impl RNG {
    pub fn new(alg: &str) -> Result<RNG> {
        Ok(RNG {
            drbg: Box::new(drbg::HmacDrbg::new(alg)?),
        })
    }

    pub fn generate_random(&mut self, buffer: &mut [u8]) -> Result<()> {
        let noaddtl: [u8; 0] = [];
        match self.drbg.generate(&noaddtl, buffer) {
            Ok(()) => Ok(()),
            Err(error) => {
                crate::misc::zeromem(buffer);
                Err(error)
            }
        }
    }

    pub fn add_seed(&mut self, buffer: &[u8]) -> Result<()> {
        #[cfg(feature = "fips")]
        {
            let no_entropy: [u8; 0] = [];
            self.drbg.reseed(&no_entropy, buffer)
        }
        #[cfg(not(feature = "fips"))]
        {
            let no_additional_input: [u8; 0] = [];
            self.drbg.reseed(buffer, &no_additional_input)
        }
    }
}

// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use std::io;

use super::EntropyError;

pub(super) fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
    let mut offset = 0;
    while offset < out.len() {
        let remaining = &mut out[offset..];
        // SAFETY: `remaining` is writable for the length passed to getrandom.
        let count = unsafe {
            libc::getrandom(
                remaining.as_mut_ptr().cast(),
                remaining.len(),
                libc::GRND_RANDOM,
            )
        };
        if count < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(EntropyError::Source);
        }
        if count == 0 {
            return Err(EntropyError::Source);
        }
        let count = usize::try_from(count).map_err(|_| EntropyError::Source)?;
        if count > remaining.len() {
            return Err(EntropyError::Source);
        }
        offset += count;
    }
    Ok(())
}

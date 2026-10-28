//! `crypto.getRandomValues` (Web Crypto), which libauth's
//! `generateRandomBytesUnchecked` (`key/key-utils.ts`) uses as its default
//! source of randomness.

/// Fill `array` with cryptographically-random bytes from the operating
/// system's random source (`/dev/urandom` on Unix-like platforms).
pub fn get_random_values(array: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(|error| format!("Unable to open the system random source: {error}"))?;
        file.read_exact(array)
            .map_err(|error| format!("Unable to read the system random source: {error}"))
    }
    #[cfg(not(unix))]
    {
        let _ = array;
        Err("No cryptographically secure random source is available on this platform.".to_string())
    }
}

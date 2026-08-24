//! RFC 4122 v4 UUID generation, mirroring `generateUUID` in upstream mirror.go.

use rand::RngCore;

/// Generates a random RFC 4122 version 4 UUID string, e.g.
/// `12345678-1234-4234-8234-123456789abc`.
pub fn generate_uuid() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // Version 4
    b[8] = (b[8] & 0x3f) | 0x80; // Variant 10

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_v4_with_correct_shape() {
        let u = generate_uuid();
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Version nibble is 4, variant nibble is 8/9/a/b.
        assert_eq!(u.as_bytes()[14], b'4');
    }

    #[test]
    fn unique() {
        let a = generate_uuid();
        let b = generate_uuid();
        assert_ne!(a, b);
    }
}

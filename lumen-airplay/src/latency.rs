//! Playout latency configuration, ported from upstream `latency.go`.

use std::sync::atomic::{AtomicI64, Ordering};

pub const DEFAULT_TARGET_LATENCY_NS: i64 = 1_000_000; // 1 ms

/// Conservative playout lead for receivers without a robust jitter buffer
/// (third-party AirPlay implementations such as Roku). 100 ms matches the
/// upstream lumen fork's `-target-latency-ms` default; larger values
/// (the original 500 ms) add noticeable video lag on video-only sessions.
pub const CONSERVATIVE_PLAYOUT_LATENCY_NS: i64 = 100_000_000; // 100 ms

static TARGET_LATENCY_NS: AtomicI64 = AtomicI64::new(DEFAULT_TARGET_LATENCY_NS);

/// Sets the desired end-to-end playout latency target (clamped to
/// [5 ms, 2 s]).
pub fn set_target_latency(d: std::time::Duration) {
    let mut ns = d.as_nanos() as i64;
    if ns < 5_000_000 {
        ns = 5_000_000;
    }
    if ns > 2_000_000_000 {
        ns = 2_000_000_000;
    }
    TARGET_LATENCY_NS.store(ns, Ordering::Relaxed);
}

pub fn target_latency() -> std::time::Duration {
    let ns = TARGET_LATENCY_NS.load(Ordering::Relaxed);
    if ns <= 0 {
        return std::time::Duration::from_nanos(DEFAULT_TARGET_LATENCY_NS as u64);
    }
    std::time::Duration::from_nanos(ns as u64)
}

pub fn target_latency_samples_44k1() -> u32 {
    samples_for_44k1(target_latency())
}

/// Rounds a duration to 44.1 kHz audio samples.
pub fn samples_for_44k1(d: std::time::Duration) -> u32 {
    let samples = (d.as_secs_f64() * 44100.0).round() as i64;
    if samples < 1 {
        return 1;
    }
    samples.min(u32::MAX as i64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_clamping() {
        set_target_latency(std::time::Duration::from_millis(1));
        assert!(target_latency() >= std::time::Duration::from_millis(5));
        set_target_latency(std::time::Duration::from_secs(10));
        assert!(target_latency() <= std::time::Duration::from_secs(2));
        set_target_latency(std::time::Duration::from_millis(100));
        assert_eq!(target_latency(), std::time::Duration::from_millis(100));
    }

    #[test]
    fn sample_conversion() {
        // 100 ms at 44100 Hz ≈ 4410 samples.
        let s = samples_for_44k1(std::time::Duration::from_millis(100));
        assert!((4409..=4411).contains(&s));
    }
}

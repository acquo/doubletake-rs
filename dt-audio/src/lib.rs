//! dt-audio — Windows system audio capture (WASAPI loopback).
//!
//! Captures whatever the default render device is playing (including other
//! applications' output) and emits interleaved S16LE stereo frames of
//! [`FRAME_SAMPLES`] samples at 44100 Hz, ready for ALAC encoding.

pub mod wasapi;

pub use wasapi::{start, AudioError, LoopbackCapture, CHANNELS, FRAME_SAMPLES, SAMPLE_RATE};

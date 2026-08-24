//! Generates FFI bindings for the NVIDIA Video Codec SDK (nvEncodeAPI.h,
//! vendored from FFmpeg's nv-codec-headers, MIT licensed).

use std::path::PathBuf;

fn main() {
    // Official NVIDIA Video Codec SDK 12.1 header (extracted from the
    // nvidia-video-codec-sdk crate bundle). The FFmpeg-maintained
    // nv-codec-headers has divergent struct layouts that the driver rejects.
    let header = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../third_party/official/nvEncodeAPI.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        // The whole header is one self-contained C API; generate everything.
        .layout_tests(false)
        .generate()
        .expect("bindgen failed on nvEncodeAPI.h");

    bindings
        .write_to_file(out_dir.join("nvenc_bindings.rs"))
        .expect("write bindings");
}

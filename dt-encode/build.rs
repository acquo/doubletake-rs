//! Generates FFI bindings for the NVIDIA Video Codec SDK (nvEncodeAPI.h,
//! vendored from FFmpeg's nv-codec-headers, MIT licensed).

use std::path::PathBuf;

fn main() {
    let header = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../third_party/nv-codec-headers/include/ffnvcodec/nvEncodeAPI.h");
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

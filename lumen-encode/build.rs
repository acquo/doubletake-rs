//! Generates FFI bindings for:
//!   1. NVIDIA Video Codec SDK (nvEncodeAPI.h, vendored, MIT licensed).
//!   2. Intel oneVPL / Media SDK (mfx.h from MSYS2's ucrt64 package) so the
//!      QSV backend can drive libvpl via runtime loading.
//!
//! The MSYS2 header path is machine-specific (this box installs oneVPL there);
//! set `LUMEN_VPL_INCLUDE` to override where mfx.h lives.

use std::path::PathBuf;

fn main() {
    // ---- NVIDIA (existing) ----
    let nv_header = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../third_party/official/nvEncodeAPI.h");
    println!("cargo:rerun-if-changed={}", nv_header.display());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let nv = bindgen::Builder::default()
        .header(nv_header.to_string_lossy())
        .layout_tests(false)
        .generate()
        .expect("bindgen failed on nvEncodeAPI.h");
    nv.write_to_file(out_dir.join("nvenc_bindings.rs"))
        .expect("write nvenc bindings");

    // ---- Intel oneVPL (mfx.h) ----
    let vpl_include = PathBuf::from(
        std::env::var("LUMEN_VPL_INCLUDE")
            .unwrap_or_else(|_| "C:/msys64/ucrt64/include/vpl".into()),
    );
    let mfx_header = vpl_include.join("mfx.h");
    if mfx_header.exists() {
        println!("cargo:rerun-if-changed={}", mfx_header.display());
        println!("cargo:rustc-cfg=has_vpl");
        let mfx = bindgen::Builder::default()
            .header(mfx_header.to_string_lossy())
            .clang_arg(format!("-I{}", vpl_include.display()))
            .allowlist_type("mfx.*")
            .allowlist_function("MFX.*")
            .layout_tests(false)
            .generate()
            .expect("bindgen failed on mfx.h");
        mfx.write_to_file(out_dir.join("qsv_bindings.rs"))
            .expect("write qsv bindings");
    }
}

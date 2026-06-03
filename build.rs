use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(pqclean_skipped)");
    let target = env::var("TARGET").unwrap_or_default();

    // Skip C compilation and cbindgen for WASM builds
    if target.contains("wasm") {
        println!(
            "cargo:warning=WASM target detected ({}), skipping PQClean C build",
            target
        );
        return;
    }

    let pqclean_built = if target.contains("ios") {
        build_pqclean_ios(&target)
    } else if target.contains("android") {
        build_pqclean_android(&target)
    } else {
        build_pqclean_desktop()
    };

    if !pqclean_built {
        println!("cargo:rustc-cfg=pqclean_skipped");
    }

    generate_c_header();
    println!("cargo:rerun-if-changed=build.rs");
}

fn pqclean_paths(manifest_dir: &PathBuf) -> Option<(PathBuf, PathBuf)> {
    let clean = manifest_dir.join("pqclean/crypto_sign/ml-dsa-44/clean");
    let common = manifest_dir.join("pqclean/common");
    if clean.exists() && common.exists() {
        Some((clean, common))
    } else {
        None
    }
}

fn add_pqclean_sources(
    build: &mut cc::Build,
    clean: &PathBuf,
    common: &PathBuf,
    manifest_dir: &PathBuf,
) -> bool {
    let clean_files = [
        "api.c",
        "sign.c",
        "poly.c",
        "packing.c",
        "polyvec.c",
        "ntt.c",
        "reduce.c",
        "rounding.c",
        "symmetric-shake.c",
    ];
    for f in &clean_files {
        let p = clean.join(f);
        if p.exists() {
            build.file(p);
        }
    }
    let fips202 = common.join("fips202.c");
    if !fips202.exists() {
        return false;
    }
    build.file(fips202);
    if common.join("keccak1600.c").exists() {
        build.file(common.join("keccak1600.c"));
    }
    let wrapper = manifest_dir.join("pqclean/acegf_wrapper.c");
    if wrapper.exists() {
        build.file(wrapper);
    }
    true
}

/// Desktop (host) build. Returns false if paths missing or build skipped.
fn build_pqclean_desktop() -> bool {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let (clean, common) = match pqclean_paths(&manifest_dir) {
        Some(p) => p,
        None => {
            println!("cargo:warning=PQClean path missing, skipping C build; PQC will use stub.");
            return false;
        }
    };
    let mut build = cc::Build::new();
    build
        .include(&clean)
        .include(&common)
        .flag_if_supported("-std=c99");
    if !add_pqclean_sources(&mut build, &clean, &common, &manifest_dir) {
        println!("cargo:warning=Missing fips202.c, skipping PQClean build");
        return false;
    }
    build.compile("pqclean_ml_dsa_44");
    true
}

/// Cross-compile PQClean for iOS (device or simulator).
fn build_pqclean_ios(target: &str) -> bool {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let (clean, common) = match pqclean_paths(&manifest_dir) {
        Some(p) => p,
        None => {
            println!("cargo:warning=PQClean path missing for iOS, skipping; PQC will use stub.");
            return false;
        }
    };

    let sdk_name = if target.contains("sim") || target == "x86_64-apple-ios" {
        "iphonesimulator"
    } else {
        "iphoneos"
    };
    let sdk_output = Command::new("xcrun")
        .args(["--sdk", sdk_name, "--show-sdk-path"])
        .output();
    let sdk_path = match sdk_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            println!(
                "cargo:warning=iOS SDK not found (xcrun --sdk {}), skipping PQClean",
                sdk_name
            );
            return false;
        }
    };

    // Match Rust's iOS deployment target (e.g. 10.0) to avoid version mismatch and
    // use -fno-stack-check so we don't need ___chkstk_darwin (not linked by rustc for iOS).
    let is_sim = target.contains("sim") || target == "x86_64-apple-ios";
    let min_version = env::var("IPHONEOS_DEPLOYMENT_TARGET").unwrap_or_else(|_| "10.0".to_string());
    let version_flag = if is_sim {
        format!("-mios-simulator-version-min={}", min_version)
    } else {
        format!("-mios-version-min={}", min_version)
    };

    let mut build = cc::Build::new();
    build
        .include(&clean)
        .include(&common)
        .flag("-std=c99")
        .flag("-target")
        .flag(target)
        .flag("-isysroot")
        .flag(&sdk_path)
        .flag(&version_flag)
        .flag("-fno-stack-check");
    if !add_pqclean_sources(&mut build, &clean, &common, &manifest_dir) {
        return false;
    }
    if let Err(e) = build.try_compile("pqclean_ml_dsa_44") {
        println!(
            "cargo:warning=iOS PQClean build failed: {}, PQC will use stub",
            e
        );
        return false;
    }
    true
}

/// Cross-compile PQClean for Android using NDK.
/// NDK clang wrapper naming: <target><api>-clang e.g. aarch64-linux-android24-clang
fn build_pqclean_android(target: &str) -> bool {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let (clean, common) = match pqclean_paths(&manifest_dir) {
        Some(p) => p,
        None => {
            println!(
                "cargo:warning=PQClean path missing for Android, skipping; PQC will use stub."
            );
            return false;
        }
    };

    let ndk_home = match env::var("ANDROID_NDK_HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            println!("cargo:warning=ANDROID_NDK_HOME not set, skipping Android PQClean; PQC will use stub.");
            return false;
        }
    };
    let ndk = PathBuf::from(&ndk_home);
    let host = if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "darwin-aarch64"
        } else {
            "darwin-x86_64"
        }
    } else if cfg!(target_os = "linux") {
        if cfg!(target_arch = "aarch64") {
            "linux-aarch64"
        } else {
            "linux-x86_64"
        }
    } else {
        println!("cargo:warning=Unsupported host for Android NDK, skipping PQClean");
        return false;
    };
    let api_level = env::var("ANDROID_NDK_API").unwrap_or_else(|_| "24".to_string());
    let llvm_bin = ndk.join("toolchains/llvm/prebuilt").join(host).join("bin");
    if !llvm_bin.exists() {
        println!(
            "cargo:warning=NDK llvm bin not found at {}, skipping PQClean",
            llvm_bin.display()
        );
        return false;
    }
    // NDK uses armv7a-linux-androideabi for clang wrapper, Rust uses armv7-linux-androideabi
    let ndk_triple = if target == "armv7-linux-androideabi" {
        "armv7a-linux-androideabi"
    } else {
        target
    };
    let clang_name = format!("{}{}-clang", ndk_triple, api_level);
    let clang = llvm_bin.join(&clang_name);
    if !clang.exists() {
        println!(
            "cargo:warning=NDK clang not found ({}), skipping PQClean; PQC will use stub",
            clang.display()
        );
        return false;
    }

    let mut build = cc::Build::new();
    build
        .include(&clean)
        .include(&common)
        .flag("-std=c99")
        .compiler(&clang);
    if !add_pqclean_sources(&mut build, &clean, &common, &manifest_dir) {
        return false;
    }
    if let Err(e) = build.try_compile("pqclean_ml_dsa_44") {
        println!(
            "cargo:warning=Android PQClean build failed: {}, PQC will use stub",
            e
        );
        return false;
    }
    true
}

fn generate_c_header() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("include");

    std::fs::create_dir_all(&output_dir).ok();

    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        cpp_compat: true,
        include_guard: Some("ACEGF_H".to_string()),
        no_includes: false,
        includes: vec![
            "stdint.h".to_string(),
            "stdbool.h".to_string(),
            "stddef.h".to_string(),
        ],
        sys_includes: vec![],
        autogen_warning: Some(
            "/* Warning: This file is auto-generated by cbindgen. Do not modify manually. */"
                .to_string(),
        ),
        documentation: true,
        documentation_style: cbindgen::DocumentationStyle::C99,
        ..Default::default()
    };

    if let Ok(bindings) = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        bindings.write_to_file(output_dir.join("acegf.h"));
        println!("cargo:rerun-if-changed=src/ffi.rs");
    }
}

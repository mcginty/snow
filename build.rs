use rustc_version::{version_meta, Channel};
use std::env;

fn main() {
    if env::var("CARGO_FEATURE_SODIUMOXIDE").is_ok() {
        println!(
            "cargo:warning=Use of the sodiumoxide backend is deprecated, as it is no longer \
             maintained; please consider switching to another resolver."
        )
    }
    if version_meta().unwrap().channel == Channel::Nightly {
        println!("cargo:rustc-cfg=feature=\"nightly\"");
    }
}

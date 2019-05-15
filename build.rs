extern crate cc;

const SABER_SRCS: [&str; 9] = [
    "saber/pack_unpack.c",
    "saber/poly.c",
    "saber/rng.c",
    "saber/fips202.c",
    "saber/verify.c",
    "saber/recon.c",
    "saber/cbd.c",
    "saber/SABER_indcpa.c",
    "saber/kem.c",
];

fn main() {
    if std::env::var("CARGO_FEATURE_REFTEST") == Ok("1".to_string()) {
        // Build saber reference implementation only when testing
        cc::Build::new().files(&SABER_SRCS).compile("saber");
        println!("# The native saber sources need libcrypto");
        println!("cargo:rustc-link-lib=dylib=crypto");
    }
}

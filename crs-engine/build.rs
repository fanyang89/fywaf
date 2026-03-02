//! Build script for crs-engine.
//!
//! Parses the CRS `.conf` files at build time and serializes the rule set to
//! JSON, which is then embedded into the WASM binary via `include_str!`.
//!
//! The CRS rules are read from `../vendor/coreruleset/rules/` relative to the
//! workspace root.  If the vendor directory is absent (e.g. the submodule was
//! not initialized) we emit a warning and write an empty rule set so the build
//! still succeeds.

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // The workspace root is one level above the crate manifest.
    let workspace_root = manifest.parent().unwrap();
    let rules_dir = workspace_root.join("vendor/coreruleset/rules");

    // Tell cargo to re-run this script if the vendor directory changes.
    println!("cargo:rerun-if-changed={}", rules_dir.display());

    let conf_files = [
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    ];

    let mut all_rules: Vec<crs_parser::Rule> = Vec::new();

    if rules_dir.exists() {
        for filename in &conf_files {
            let path = rules_dir.join(filename);
            println!("cargo:rerun-if-changed={}", path.display());
            match crs_parser::parse_conf(&path) {
                Ok(rules) => {
                    eprintln!("crs-build: parsed {} rules from {}", rules.len(), filename);
                    all_rules.extend(rules);
                }
                Err(e) => {
                    eprintln!("crs-build: warning: could not parse {filename}: {e}");
                }
            }
        }
    } else {
        eprintln!(
            "crs-build: warning: vendor/coreruleset not found — \
             run `git submodule update --init` to populate it. \
             Building with empty rule set."
        );
    }

    let json = serde_json::to_string(&all_rules).expect("failed to serialize rules to JSON");

    let out_path = out_dir.join("crs_rules.json");
    std::fs::write(&out_path, &json).expect("failed to write crs_rules.json");

    eprintln!(
        "crs-build: wrote {} rules ({} bytes) to {}",
        all_rules.len(),
        json.len(),
        out_path.display()
    );
}

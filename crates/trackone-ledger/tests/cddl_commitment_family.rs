use std::collections::BTreeSet;
use std::path::PathBuf;

use cddl::cddl_from_str;

fn cddl_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/unified/cddl/commitment-artifacts-v1.cddl")
}

#[test]
fn commitment_family_cddl_parses() {
    let path = cddl_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    cddl_from_str(&source, false)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
}

#[test]
fn commitment_family_cddl_exposes_expected_top_level_rules() {
    let path = cddl_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let ast = cddl_from_str(&source, false)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    let rule_names: BTreeSet<_> = ast.rules.iter().map(|rule| rule.name()).collect();

    for expected in [
        "fact-json-projection-v1",
        "env-fact-v1",
        "fact-v1",
        "block-header-v1",
        "day-record-v1",
    ] {
        assert!(
            rule_names.contains(expected),
            "missing top-level CDDL rule {expected}"
        );
    }
}

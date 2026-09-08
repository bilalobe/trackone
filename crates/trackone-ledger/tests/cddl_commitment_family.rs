use std::collections::BTreeSet;
use std::path::PathBuf;

use cddl::cddl_from_str;

#[test]
fn vtl_cddl_parses_and_exposes_the_authoritative_rules() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/unified/cddl/vtl-artifacts.cddl");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let ast = cddl_from_str(&source, false)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
    let names = ast
        .rules
        .iter()
        .map(|rule| rule.name())
        .collect::<BTreeSet<_>>();
    for expected in [
        "producer-manifest",
        "verifier-result",
        "segment-record",
        "segment-closure-policy",
        "sha256-value",
    ] {
        assert!(
            names.contains(expected),
            "missing top-level CDDL rule {expected}"
        );
    }
}

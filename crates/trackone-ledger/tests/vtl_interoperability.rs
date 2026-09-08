use trackone_ledger::vtl::{
    COMMITMENT_PROFILE_ID, ClosurePolicy, EmptyMode, SEGMENT_MEDIA_TYPE,
    SPECIALIZED_SEGMENT_MEDIA_TYPE, SegmentRecord, batch_roots_from_leaf_hashes,
    compose_batch_roots, merkle_root_from_leaf_hashes, merkle_root_from_records,
    validate_canonical_record,
};

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

fn normative_epoch_bytes() -> Vec<u8> {
    let records = [
        "87014800000000000000010100f600f6",
        "87014800000000000000020201f600f6",
        "87014800000000000000030302f600f6",
    ]
    .map(decode_hex)
    .to_vec();
    let merkle = merkle_root_from_records(&records);
    SegmentRecord::new_epoch(
        "b7a1d5e40c6f438e9a75db27c96f31aa",
        ClosurePolicy {
            interval_ms: 86_400_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
        "interval",
        3,
        batch_roots_from_leaf_hashes(&merkle.leaf_hashes, 2).unwrap(),
        merkle.root,
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap()
}

#[test]
fn baseline_accepts_a_conforming_4096_octet_record() {
    let mut record = vec![
        0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0xf6, 0, 0x59, 0x0f, 0xee,
    ];
    record.resize(4096, 0);
    assert_eq!(record.len(), 4096);
    validate_canonical_record(&record).unwrap();
}

#[test]
fn duplicate_admissions_remain_distinct_commitment_occurrences() {
    let record = vec![
        0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0xf6, 0, 0xf6,
    ];
    validate_canonical_record(&record).unwrap();
    let single = merkle_root_from_records(std::slice::from_ref(&record));
    let duplicate = merkle_root_from_records(&[record.clone(), record]);
    assert_eq!(duplicate.leaf_hashes[0], duplicate.leaf_hashes[1]);
    assert_ne!(single.root, duplicate.root);
}

#[test]
fn normative_payload_type_vectors_retain_distinct_exact_bytes() {
    for (record_hex, leaf_hex) in [
        (
            "87014800000000000000010100f60001",
            "61d6b5be58a51d90b833cc8f2558d3b0e30a0c41cae971a81a92596013ca4e5c",
        ),
        (
            "87014800000000000000010100f600f93c00",
            "793c53c545002c8b872ff84d1f479c1243f36e4ba57dbc8b387ec52c47fe62df",
        ),
        (
            "87014800000000000000010100f600f90000",
            "5cd7c34a8083929449188288272e339f87fe06f64738b2f8f84a2c317ee40c27",
        ),
        (
            "87014800000000000000010100f600f98000",
            "a45dabed6caf13fe4901f9bd596325e65e13d006dbb1ec8f1180b671537ffccb",
        ),
    ] {
        let record = decode_hex(record_hex);
        validate_canonical_record(&record).unwrap();
        assert_eq!(merkle_root_from_records(&[record]).root_hex(), leaf_hex);
    }
}

#[test]
fn normative_duplicate_and_empty_successor_vectors_match() {
    let record = decode_hex("87014800000000000000010100f600f6");
    assert_eq!(
        merkle_root_from_records(&vec![record.clone(); 3]).root_hex(),
        "05ddc48e556d67534bf7960a70209696ca9eeb6f18d5595358e7f4804ec87701"
    );
    assert_eq!(
        merkle_root_from_records(&vec![record; 4]).root_hex(),
        "d5d26faa3f54d81d8173700a48d9286179c9d35685d464183a99b1e966f1dfd8"
    );

    let successor = SegmentRecord::new_successor(
        &normative_epoch_bytes(),
        ClosurePolicy {
            interval_ms: 86_400_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
        "shutdown",
        0,
        Vec::new(),
        trackone_ledger::sha256_digest(b""),
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap();
    assert_eq!(successor.len(), 394);
    assert_eq!(
        trackone_ledger::sha256_hex(&successor),
        "cde8b546adc5afa446195bb9cc4e519d4bd1c9529d1678bf6e076ef6d24e229e"
    );
}

#[test]
fn normative_interoperability_identifiers_are_exact() {
    assert_eq!(
        COMMITMENT_PROFILE_ID,
        "c08ade4e-1785-4eb6-9648-b7003d76288d"
    );
    assert_eq!(SEGMENT_MEDIA_TYPE, "application/cbor");
    assert_eq!(
        SPECIALIZED_SEGMENT_MEDIA_TYPE,
        "application/vnd.vtl.segment+cbor"
    );
}

#[test]
fn machine_readable_global_sort_trap_rejects_per_chunk_sorting() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../toolset/vectors/vtl-interoperability/cases.json"
    ))
    .unwrap();
    let case = &corpus["global_sort_traps"][0];
    let hex_array = |name: &str| {
        case[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let records = hex_array("records_cbor_hex_in_admission_order")
        .iter()
        .map(|value| decode_hex(value))
        .collect::<Vec<_>>();
    let batch_limit = case["batch_record_limit"].as_u64().unwrap();

    let merkle = merkle_root_from_records(&records);
    assert_eq!(
        merkle
            .leaf_hashes
            .iter()
            .map(|value| trackone_ledger::hex_lower(value))
            .collect::<Vec<_>>(),
        hex_array("expected_sorted_leaf_hashes")
    );
    let correct_batches = batch_roots_from_leaf_hashes(&merkle.leaf_hashes, batch_limit).unwrap();
    assert_eq!(
        correct_batches
            .iter()
            .map(|value| trackone_ledger::hex_lower(value))
            .collect::<Vec<_>>(),
        hex_array("expected_batch_roots")
    );
    assert_eq!(
        merkle.root_hex(),
        case["expected_segment_root"].as_str().unwrap()
    );

    let per_chunk_roots = records
        .chunks(usize::try_from(batch_limit).unwrap())
        .map(merkle_root_from_records)
        .map(|result| result.root)
        .collect::<Vec<_>>();
    assert_eq!(
        per_chunk_roots
            .iter()
            .map(|value| trackone_ledger::hex_lower(value))
            .collect::<Vec<_>>(),
        hex_array("forbidden_per_chunk_batch_roots")
    );
    let forbidden_root =
        compose_batch_roots(&per_chunk_roots, records.len() as u64, batch_limit).unwrap();
    assert_eq!(
        trackone_ledger::hex_lower(&forbidden_root),
        case["forbidden_per_chunk_segment_root"].as_str().unwrap()
    );
    assert_ne!(forbidden_root, merkle.root);
    assert_eq!(
        case["expected_public_recompute_failure_reason"]
            .as_str()
            .unwrap(),
        "commitment_mismatch"
    );
}

#[test]
fn machine_readable_record_acceptance_envelope_is_exact() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../toolset/vectors/vtl-interoperability/cases.json"
    ))
    .unwrap();
    let cases = corpus["canonical_record_acceptance_cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 2);

    let build = |case: &serde_json::Value| {
        let construction = &case["construction"];
        if let Some(encoded) = construction["record_cbor_hex"].as_str() {
            return decode_hex(encoded);
        }
        let mut record = decode_hex(construction["record_prefix_hex"].as_str().unwrap());
        let array_head = decode_hex(construction["repeated_array_head_hex"].as_str().unwrap());
        assert_eq!(array_head.len(), 1);
        record.extend(std::iter::repeat_n(
            array_head[0],
            construction["repeat_count"].as_u64().unwrap() as usize,
        ));
        let byte_string_length = construction["innermost_bstr_length"].as_u64().unwrap() as u16;
        record.push(0x59);
        record.extend_from_slice(&byte_string_length.to_be_bytes());
        let fill = decode_hex(construction["fill_octet_hex"].as_str().unwrap());
        record.extend(std::iter::repeat_n(
            fill[0],
            usize::from(byte_string_length),
        ));
        record
    };

    for case in cases {
        let record = build(case);
        assert_eq!(
            record.len(),
            case["expected_encoded_length"].as_u64().unwrap() as usize
        );
        validate_canonical_record(&record).unwrap();
        assert_eq!(
            merkle_root_from_records(&[record]).root_hex(),
            case["expected_leaf_hash"].as_str().unwrap()
        );
    }

    assert_eq!(cases[0]["payload_nesting_depth"], 16);
    assert_eq!(cases[0]["inside_baseline_acceptance_envelope"], true);
    assert!(cases[0]["permitted_rejection"].is_null());
    assert_eq!(cases[1]["payload_nesting_depth"], 17);
    assert_eq!(cases[1]["inside_baseline_acceptance_envelope"], false);
    assert_eq!(cases[1]["permitted_rejection"], "verifier_policy_rejection");
}

#[test]
fn machine_readable_five_leaf_case_exercises_recursive_composition() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../toolset/vectors/vtl-interoperability/cases.json"
    ))
    .unwrap();
    let case = &corpus["aligned_subtree_composition_cases"][0];
    let records = case["records_cbor_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| decode_hex(value.as_str().unwrap()))
        .collect::<Vec<_>>();
    let batch_limit = case["batch_record_limit"].as_u64().unwrap();
    let merkle = merkle_root_from_records(&records);
    let expected = |name: &str| {
        case[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    assert_eq!(
        merkle
            .leaf_hashes
            .iter()
            .map(|value| trackone_ledger::hex_lower(value))
            .collect::<Vec<_>>(),
        expected("expected_sorted_leaf_hashes")
    );
    let batch_roots = batch_roots_from_leaf_hashes(&merkle.leaf_hashes, batch_limit).unwrap();
    assert_eq!(
        batch_roots
            .iter()
            .map(|value| trackone_ledger::hex_lower(value))
            .collect::<Vec<_>>(),
        expected("expected_batch_roots")
    );
    assert_eq!(
        trackone_ledger::hex_lower(&merkle_root_from_leaf_hashes(&merkle.leaf_hashes[..4])),
        case["expected_left_range_root"].as_str().unwrap()
    );
    assert_eq!(
        trackone_ledger::hex_lower(
            &compose_batch_roots(&batch_roots, records.len() as u64, batch_limit).unwrap()
        ),
        case["expected_segment_root"].as_str().unwrap()
    );
    assert_eq!(
        merkle.root_hex(),
        case["expected_segment_root"].as_str().unwrap()
    );
}

use sha2::{Digest, Sha256};
use trackone_ledger::vtl::{
    COMMITMENT_PROFILE_ID, ClosurePolicy, EmptyMode, SegmentRecord, batch_roots_from_leaf_hashes,
    decode_segment_record, merkle_root_from_records, validate_canonical_record,
};

#[test]
fn rust_reproduces_normative_vtl_known_answer_vector() {
    assert_eq!(
        COMMITMENT_PROFILE_ID,
        "c08ade4e-1785-4eb6-9648-b7003d76288d"
    );
    let records = [
        "87014800000000000000010100f600f6",
        "87014800000000000000020201f600f6",
        "87014800000000000000030302f600f6",
    ]
    .map(|value| hex::decode(value).unwrap())
    .to_vec();
    for record in &records {
        validate_canonical_record(record).unwrap();
    }
    let merkle = merkle_root_from_records(&records);
    assert_eq!(
        merkle.root_hex(),
        "bc6502552ed0c515f58d1c632e54db37594042609b59838eb0d5b3d5842aa054"
    );
    let batch_roots = batch_roots_from_leaf_hashes(&merkle.leaf_hashes, 2).unwrap();
    assert_eq!(
        trackone_ledger::hex_lower(&batch_roots[0]),
        "554491e4edf28061622396b83a870db4652211557127c664c6be1c4ad66471ff"
    );
    assert_eq!(
        trackone_ledger::hex_lower(&batch_roots[1]),
        "b83bc27f2d8be3a66373af24e6af3eeffff99ff0696ae18c70e379e853796d26"
    );

    let segment = SegmentRecord::new_epoch(
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
        batch_roots,
        merkle.root,
    )
    .unwrap();
    let expected = hex::decode(concat!(
        "aa6776657273696f6e01696c65646765725f6964782062376131643565343063",
        "366634333865396137356462323763393666333161616b62617463685f726f6f",
        "7473825820554491e4edf28061622396b83a870db4652211557127c664c6be1c",
        "4ad66471ff5820b83bc27f2d8be3a66373af24e6af3eeffff99ff0696ae18c70",
        "e379e853796d266c636c6f73655f726561736f6e68696e74657276616c6c7265",
        "636f72645f636f756e74036c7365676d656e745f726f6f745820bc6502552ed0",
        "c515f58d1c632e54db37594042609b59838eb0d5b3d5842aa0546e636c6f7375",
        "72655f706f6c696379a66776657273696f6e016a656d7074795f6d6f64656873",
        "757070726573736b696e74657276616c5f6d731a05265c006c7265636f72645f",
        "6c696d6974f67073697a655f6c696d69745f6279746573f67262617463685f72",
        "65636f72645f6c696d6974026e7365676d656e745f6e756d6265720073707265",
        "765f7365676d656e745f73686132353658200000000000000000000000000000",
        "00000000000000000000000000000000000075636f6d6d69746d656e745f7072",
        "6f66696c655f6964782463303861646534652d313738352d346562362d393634",
        "382d623730303364373632383864"
    ))
    .unwrap();
    assert_eq!(segment.canonical_cbor_bytes().unwrap(), expected);
    assert_eq!(expected.len(), 462);
    assert_eq!(
        trackone_ledger::hex_lower(Sha256::digest(&expected).as_ref()),
        "2672cb72d5f06863110af1b30660c7e5ba495c0b2ce7d084b0436e010e99388d"
    );
    assert_eq!(decode_segment_record(&expected).unwrap(), segment);
}

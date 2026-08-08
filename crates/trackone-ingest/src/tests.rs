use super::*;
#[cfg(feature = "xchacha")]
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use heapless::Vec as HVec;
#[cfg(feature = "xchacha")]
use trackone_core::AEAD_TAG_LEN;
use trackone_core::crypto::dummy::DummyAead;
use trackone_core::crypto::{AeadDecrypt, AeadEncrypt};
use trackone_core::{
    AEAD_NONCE_LEN, EnvFact, Error, Fact, FactKind, FactPayload, MAX_FACT_LEN, PodId, SampleType,
};

fn sample_fact() -> Fact {
    Fact {
        pod_id: PodId::from(0x1234u32),
        fc: 7,
        ingest_time: 0,
        pod_time: Some(1_700_000_000),
        kind: FactKind::Env,
        payload: FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        ),
    }
}

struct InspectAead {
    expected_aad: [u8; 4],
}

impl InspectAead {
    const fn new(expected_aad: [u8; 4]) -> Self {
        Self { expected_aad }
    }
}

impl AeadEncrypt for InspectAead {
    type Error = Error;

    fn encrypt(
        &self,
        _nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        assert_eq!(aad, self.expected_aad);
        out[..plaintext.len()].copy_from_slice(plaintext);
        Ok(plaintext.len())
    }
}

impl AeadDecrypt for InspectAead {
    type Error = Error;

    fn decrypt(
        &self,
        _nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        assert_eq!(aad, self.expected_aad);
        out[..ciphertext.len()].copy_from_slice(ciphertext);
        Ok(ciphertext.len())
    }
}

#[test]
fn profile_accepts_omitted_or_rust_postcard_only() {
    assert!(is_supported_ingest_profile(None));
    assert!(is_supported_ingest_profile(Some(
        INGEST_PROFILE_RUST_POSTCARD_V1
    )));
    assert!(!is_supported_ingest_profile(Some("python-tlv-legacy")));
}

#[test]
fn framed_aad_uses_legacy_dev_id_msg_type_and_flags() {
    assert_eq!(
        framed_aad_for_pod(PodId::from(0x1234u32), 1, 0),
        [0x12, 0x34, 1, 0]
    );
}

#[test]
fn framed_nonce_uses_salt_counter_and_tail() {
    let nonce = framed_nonce([0x11; 8], 7, [0x22; 8]);
    assert_eq!(&nonce[..8], &[0x11; 8]);
    assert_eq!(
        u64::from_be_bytes(nonce[8..16].try_into().expect("counter bytes")),
        7
    );
    assert_eq!(&nonce[16..24], &[0x22; 8]);
    assert_eq!(validate_nonce_prefix(&nonce, &[0x11; 8], 7), Ok(()));
}

#[test]
fn nonce_validation_rejects_mismatches() {
    let nonce = framed_nonce([0x11; 8], 7, [0x22; 8]);
    assert_eq!(
        validate_nonce_prefix(&nonce[..23], &[0x11; 8], 7),
        Err(FramedNonceError::NonceLength)
    );
    assert_eq!(
        validate_nonce_prefix(&nonce, &[0x11; 7], 7),
        Err(FramedNonceError::Salt8Length)
    );
    assert_eq!(
        validate_nonce_prefix(&nonce, &[0x12; 8], 7),
        Err(FramedNonceError::SaltMismatch)
    );
    assert_eq!(
        validate_nonce_prefix(&nonce, &[0x11; 8], 8),
        Err(FramedNonceError::FrameCounterMismatch)
    );
}

#[test]
fn postcard_fact_roundtrips_and_validates_frame_binding() {
    let fact = sample_fact();
    let (encoded, used) = encode_fact_postcard_buf(&fact).expect("encode");
    let decoded = decode_fact_postcard(&encoded[..used]).expect("decode");
    let expected_pod_id = PodId::from(0x1234u32);

    assert_eq!(decoded, fact);
    assert_eq!(validate_fact_binding(&decoded, expected_pod_id, 7), Ok(()));
    assert_eq!(
        validate_fact_binding(&decoded, PodId::from(0x5678u32), 7),
        Err(FramedFactBindingError::PodIdMismatch)
    );
    assert_eq!(
        validate_fact_binding(&decoded, expected_pod_id, 8),
        Err(FramedFactBindingError::FrameCounterMismatch)
    );
}

#[test]
fn postcard_fact_decode_rejects_invalid_semantics() {
    let mut fact = sample_fact();
    fact.kind = FactKind::Health;
    let mut encoded = [0u8; MAX_FACT_LEN];
    let used = postcard::to_slice(&fact, &mut encoded).expect("serialize invalid fixture");

    assert!(matches!(
        decode_fact_postcard(used),
        Err(Error::InvalidFact(_))
    ));
    assert!(matches!(
        encode_fact_postcard(&fact, &mut encoded),
        Err(Error::InvalidFact(_))
    ));
}

#[test]
fn fact_binding_rejects_a_different_full_pod_id_with_the_same_legacy_suffix() {
    let expected_pod_id = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x12, 0x34]);
    let mut fact = sample_fact();
    fact.pod_id = PodId::from([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x12, 0x34]);

    assert_eq!(
        legacy_dev_id_from_pod_id(fact.pod_id),
        legacy_dev_id_from_pod_id(expected_pod_id)
    );
    assert_eq!(
        validate_fact_binding(&fact, expected_pod_id, 7),
        Err(FramedFactBindingError::PodIdMismatch)
    );
}

#[test]
fn fact_encrypt_decrypt_roundtrip() {
    static KEY: &[u8] = b"frame-test-key";
    let cipher = DummyAead::new(KEY);
    let fact = make_fact(
        PodId::from(5u32),
        1,
        FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 20.0).unwrap(),
        ),
    )
    .unwrap();

    let nonce = [0u8; AEAD_NONCE_LEN];
    let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
    let dec = decrypt_fact::<128, _>(&cipher, &enc, fact.pod_id).expect("decrypt fact");

    assert_eq!(fact, dec);
}

#[test]
fn generic_decrypt_rejects_same_suffix_full_identity_substitution() {
    let expected_pod_id = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x12, 0x34]);
    let forged_pod_id = PodId::from([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x12, 0x34]);
    let cipher = DummyAead::new(b"frame-test-key");
    let fact = make_fact(
        forged_pod_id,
        1,
        FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 20.0).unwrap(),
        ),
    )
    .unwrap();
    let mut frame =
        encrypt_fact::<128, _>(&cipher, [0; AEAD_NONCE_LEN], &fact).expect("encrypt fact");

    // The legacy AAD is unchanged because both identities have the same
    // suffix. Exact post-decryption binding must still reject the payload.
    assert_eq!(
        legacy_dev_id_from_pod_id(expected_pod_id),
        legacy_dev_id_from_pod_id(forged_pod_id)
    );
    frame.pod_id = expected_pod_id;

    assert_eq!(
        decrypt_fact::<128, _>(&cipher, &frame, expected_pod_id),
        Err(Error::CryptoError)
    );
}

#[test]
fn fact_encrypt_decrypt_use_dev_id_msg_type_flags_aad() {
    let cipher = InspectAead::new([0x12, 0x34, 1, 0]);
    let fact = make_fact(
        PodId::from(0x1234u32),
        1,
        FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 20.0).unwrap(),
        ),
    )
    .unwrap();

    let nonce = [0u8; AEAD_NONCE_LEN];
    let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
    let dec = decrypt_fact::<128, _>(&cipher, &enc, fact.pod_id).expect("decrypt fact");

    assert_eq!(fact, dec);
}

#[test]
fn fact_serialization_within_max_len() {
    let fact = make_fact(
        PodId::from(99u32),
        12345,
        FactPayload::Env(
            EnvFact::summary(
                SampleType::AmbientRelativeHumidity,
                1_700_000_000,
                1_700_003_600,
                50.0,
                70.0,
                60.0,
                144,
            )
            .unwrap(),
        ),
    )
    .unwrap();

    let mut buf = [0u8; MAX_FACT_LEN];
    let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");
    assert!(
        used.len() <= MAX_FACT_LEN,
        "Fact serialized length {} > MAX_FACT_LEN",
        used.len()
    );
}

#[test]
fn encrypt_fact_ciphertext_buffer_too_small() {
    static KEY: &[u8] = b"test-key";
    let cipher = DummyAead::new(KEY);
    let fact = make_fact(
        PodId::from(1u32),
        1,
        FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 20.0).unwrap(),
        ),
    )
    .unwrap();

    let result = encrypt_fact::<1, _>(&cipher, [0u8; AEAD_NONCE_LEN], &fact);
    assert!(result.is_err(), "should fail with small buffer");
}

#[test]
fn decrypt_fact_corrupted_ciphertext() {
    static KEY: &[u8] = b"test-key";
    let cipher = DummyAead::new(KEY);
    let fact = make_fact(
        PodId::from(5u32),
        1,
        FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 20.0).unwrap(),
        ),
    )
    .unwrap();

    let mut enc =
        encrypt_fact::<128, _>(&cipher, [0u8; AEAD_NONCE_LEN], &fact).expect("encrypt fact");
    if !enc.ciphertext.is_empty() {
        enc.ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_fact::<128, _>(&cipher, &enc, fact.pod_id);
    if let Ok(decoded) = result {
        assert_ne!(decoded, fact);
    }
}

#[test]
fn decrypt_fact_buffer_size_mismatch() {
    let cipher = DummyAead::new(b"test-key");
    let mut large_ciphertext = HVec::<u8, 512>::new();
    for i in 0..300 {
        large_ciphertext.push((i % 256) as u8).unwrap();
    }

    let frame = EncryptedFrame::<512> {
        pod_id: PodId::from(42u32),
        fc: 100,
        nonce: [0u8; AEAD_NONCE_LEN],
        ciphertext: large_ciphertext,
    };

    let result = decrypt_fact::<512, _>(&cipher, &frame, frame.pod_id);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::DeserializeError);
}

#[cfg(feature = "std")]
#[test]
fn replay_window_accepts_and_prunes() {
    let mut state = ReplayWindow::new(3, Some(1));

    state.check_and_update(2).expect("fc=2");
    state.check_and_update(3).expect("fc=3");
    state.check_and_update(4).expect("fc=4");
    state.check_and_update(5).expect("fc=5");

    assert_eq!(state.highest_fc_seen(), Some(5));
    assert_eq!(state.seen_fcs(), vec![2, 3, 4, 5]);
}

#[cfg(feature = "std")]
#[test]
fn replay_window_rejects_duplicates_and_out_of_window() {
    let mut state = ReplayWindow::new(4, Some(10));

    assert_eq!(
        state.check_and_update(10).unwrap_err(),
        RejectReason::Duplicate
    );
    assert_eq!(
        state.check_and_update(5).unwrap_err(),
        RejectReason::OutOfWindow
    );
    assert_eq!(
        state.check_and_update(20).unwrap_err(),
        RejectReason::OutOfWindow
    );
}

#[cfg(feature = "std")]
#[test]
fn replay_snapshot_preserves_reordered_observations() {
    let mut state = ReplayWindow::new(4, None);
    state.check_and_update(10).unwrap();
    state.check_and_update(8).unwrap();
    let snapshot = state.snapshot("device-101:epoch-1").unwrap();
    let restored = ReplayWindow::from_snapshot("device-101:epoch-1", snapshot).unwrap();
    let mut restored = restored;
    assert_eq!(restored.check_and_update(10), Err(RejectReason::Duplicate));
    assert_eq!(restored.check_and_update(8), Err(RejectReason::Duplicate));
}

#[cfg(feature = "std")]
#[test]
fn replay_snapshot_requires_the_expected_nonempty_namespace() {
    let state = ReplayWindow::new(4, Some(10));
    assert_eq!(state.snapshot(""), Err(RejectReason::ReplayNamespaceEmpty));

    let snapshot = state.snapshot("device-101:epoch-1").unwrap();
    assert_eq!(
        ReplayWindow::from_snapshot("", snapshot.clone()),
        Err(RejectReason::ReplayNamespaceEmpty)
    );
    assert_eq!(
        ReplayWindow::from_snapshot("device-101:epoch-2", snapshot),
        Err(RejectReason::ReplayNamespaceMismatch)
    );
}

#[cfg(feature = "xchacha")]
fn frame_and_device_for_fact_pod_id(
    fact_pod_id: PodId,
) -> (FrameInput<'static>, [u8; 8], [u8; 32]) {
    let key = [7u8; 32];
    let salt8 = *b"salt0001";
    let fact = Fact {
        pod_id: fact_pod_id,
        fc: 3,
        ingest_time: 0,
        pod_time: Some(1_700_000_000),
        kind: FactKind::Env,
        payload: FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        ),
    };
    let (plaintext, used) = encode_fact_postcard_buf(&fact).expect("encode");
    let nonce = framed_nonce(salt8, 3, *b"rand0001");
    let aad = framed_aad(1, 1, 0);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
    let nonce_ref = (&nonce[..]).try_into().expect("checked nonce length");
    let combined = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: &plaintext[..used],
                aad: aad.as_slice(),
            },
        )
        .expect("encrypt");
    let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

    let frame = FrameInput {
        header: FrameHeader {
            dev_id: 1,
            msg_type: 1,
            fc: 3,
            flags: 0,
        },
        nonce: Box::leak(Box::new(nonce)),
        ct: Box::leak(ct.to_vec().into_boxed_slice()),
        tag: Box::leak(tag.to_vec().into_boxed_slice()),
    };
    (frame, salt8, key)
}

#[cfg(feature = "xchacha")]
fn sample_frame_and_device() -> (FrameInput<'static>, [u8; 8], [u8; 32]) {
    frame_and_device_for_fact_pod_id(PodId::from(1u32))
}

#[cfg(feature = "xchacha")]
fn sample_device_material<'a>(salt8: &'a [u8], ck_up: &'a [u8]) -> DeviceMaterial<'a> {
    DeviceMaterial::new(PodId::from(1u32), salt8, ck_up)
}

#[cfg(feature = "xchacha")]
#[test]
fn validate_and_decrypt_succeeds_for_valid_frame() {
    let (frame, salt8, key) = sample_frame_and_device();
    let accepted =
        validate_and_decrypt(frame, sample_device_material(&salt8, &key)).expect("postcard fact");

    assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
    assert_eq!(accepted.fact.fc, 3);
    assert_eq!(accepted.fact.kind, FactKind::Env);
}

#[cfg(feature = "xchacha")]
#[test]
fn admission_rejects_a_forged_full_pod_id_with_the_same_legacy_suffix() {
    let expected_pod_id = PodId::from(1u32);
    let forged_pod_id = PodId::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01]);
    assert_eq!(
        legacy_dev_id_from_pod_id(forged_pod_id),
        legacy_dev_id_from_pod_id(expected_pod_id)
    );
    let (frame, salt8, key) = frame_and_device_for_fact_pod_id(forged_pod_id);

    let err = validate_and_decrypt(frame, DeviceMaterial::new(expected_pod_id, &salt8, &key))
        .unwrap_err();

    assert_eq!(err, RejectReason::PayloadDeviceIdMismatch);
}

#[cfg(feature = "xchacha")]
#[test]
fn admission_rejects_key_material_selected_for_a_different_header_identity() {
    let (frame, salt8, key) = sample_frame_and_device();

    let err = validate_and_decrypt(frame, DeviceMaterial::new(PodId::from(2u32), &salt8, &key))
        .unwrap_err();

    assert_eq!(err, RejectReason::HeaderDeviceIdMismatch);
}

#[cfg(feature = "xchacha")]
#[test]
fn validate_and_decrypt_rejects_nonzero_flags() {
    let (frame, salt8, key) = sample_frame_and_device();
    let err = validate_and_decrypt(
        FrameInput {
            header: FrameHeader {
                flags: 1,
                ..frame.header
            },
            ..frame
        },
        sample_device_material(&salt8, &key),
    )
    .unwrap_err();
    assert_eq!(err, RejectReason::UnsupportedFlags);
}

#[cfg(feature = "xchacha")]
#[test]
fn validate_and_decrypt_rejects_non_fact_message_type_before_decryption() {
    let (frame, salt8, key) = sample_frame_and_device();
    let err = validate_and_decrypt(
        FrameInput {
            header: FrameHeader {
                msg_type: FRAMED_FACT_MSG_TYPE.wrapping_add(1),
                ..frame.header
            },
            ..frame
        },
        sample_device_material(&salt8, &key),
    )
    .unwrap_err();

    assert_eq!(err, RejectReason::UnsupportedMessageType);
}

#[cfg(feature = "xchacha")]
#[test]
fn rust_postcard_profile_rejects_legacy_tlv_plaintext() {
    let key = [7u8; 32];
    let salt8 = *b"salt0001";
    let plaintext = [0x01, 4, 0, 0, 0, 3, 0x03, 2, 0x09, 0xE0];
    let nonce = framed_nonce(salt8, 3, *b"rand0001");
    let aad = framed_aad(1, 1, 0);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
    let nonce_ref = (&nonce[..]).try_into().expect("checked nonce length");
    let combined = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .expect("encrypt");
    let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

    let frame = FrameInput {
        header: FrameHeader {
            dev_id: 1,
            msg_type: 1,
            fc: 3,
            flags: 0,
        },
        nonce: &nonce,
        ct,
        tag,
    };
    let err = validate_and_decrypt(frame, sample_device_material(&salt8, &key)).unwrap_err();
    assert_eq!(err, RejectReason::DecryptFailed);
}

#[cfg(feature = "xchacha")]
#[test]
fn postcard_fact_counter_must_match_frame_counter() {
    let key = [7u8; 32];
    let salt8 = *b"salt0001";
    let mut fact = sample_fact();
    fact.pod_id = PodId::from(1u32);
    fact.fc = 4;
    let (plaintext, used) = encode_fact_postcard_buf(&fact).expect("encode");
    let nonce = framed_nonce(salt8, 3, *b"rand0001");
    let aad = framed_aad(1, 1, 0);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
    let nonce_ref = (&nonce[..]).try_into().expect("checked nonce length");
    let combined = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: &plaintext[..used],
                aad: aad.as_slice(),
            },
        )
        .expect("encrypt");
    let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

    let err = validate_and_decrypt(
        FrameInput {
            header: FrameHeader {
                dev_id: 1,
                msg_type: 1,
                fc: 3,
                flags: 0,
            },
            nonce: &nonce,
            ct,
            tag,
        },
        sample_device_material(&salt8, &key),
    )
    .unwrap_err();
    assert_eq!(err, RejectReason::PayloadFcMismatch);
}

#[cfg(feature = "xchacha")]
#[test]
fn validate_and_decrypt_rejects_oversized_ciphertext() {
    let (frame, salt8, key) = sample_frame_and_device();
    let oversized = vec![0u8; MAX_FRAME_CIPHERTEXT_BYTES + 1];
    let err = validate_and_decrypt(
        FrameInput {
            ct: &oversized,
            ..frame
        },
        sample_device_material(&salt8, &key),
    )
    .unwrap_err();
    assert_eq!(err, RejectReason::CiphertextTooLarge);
}

#[cfg(feature = "xchacha")]
#[test]
fn emit_fixture_produces_admissible_frame() {
    let salt8 = *b"salt0001";
    let key = [7u8; 32];
    let fixture = emit_fixture(
        1,
        3,
        sample_device_material(&salt8, &key),
        1,
        0,
        Some(1_700_000_000),
    )
    .expect("fixture");

    let accepted = validate_and_decrypt(
        FrameInput {
            header: FrameHeader {
                dev_id: fixture.dev_id,
                msg_type: fixture.msg_type,
                fc: fixture.fc,
                flags: fixture.flags,
            },
            nonce: &fixture.nonce,
            ct: &fixture.ct,
            tag: &fixture.tag,
        },
        sample_device_material(&salt8, &key),
    )
    .expect("fixture decrypt");

    assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
    assert_eq!(accepted.fact.fc, 3);
}

#[cfg(feature = "xchacha")]
#[test]
fn emit_fixture_preserves_the_complete_provisioned_pod_id() {
    let salt8 = *b"salt0001";
    let key = [7u8; 32];
    let expected_pod_id = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x00, 0x01]);
    let device = DeviceMaterial::new(expected_pod_id, &salt8, &key);
    let fixture = emit_fixture(1, 3, device, 1, 0, Some(1_700_000_000)).expect("fixture");

    let accepted = validate_and_decrypt(
        FrameInput {
            header: FrameHeader {
                dev_id: fixture.dev_id,
                msg_type: fixture.msg_type,
                fc: fixture.fc,
                flags: fixture.flags,
            },
            nonce: &fixture.nonce,
            ct: &fixture.ct,
            tag: &fixture.tag,
        },
        device,
    )
    .expect("fixture decrypt");

    assert_eq!(accepted.fact.pod_id, expected_pod_id);
}

#[cfg(feature = "xchacha")]
#[test]
fn emit_fixture_rejects_a_header_for_different_provisioned_material() {
    let salt8 = *b"salt0001";
    let key = [7u8; 32];
    let err = emit_fixture(
        1,
        3,
        DeviceMaterial::new(PodId::from(2u32), &salt8, &key),
        1,
        0,
        Some(1_700_000_000),
    )
    .unwrap_err();

    assert_eq!(
        err,
        FixtureError::Reject(RejectReason::HeaderDeviceIdMismatch)
    );
}

#[cfg(feature = "xchacha")]
#[test]
fn emit_fixture_rejects_nonzero_flags() {
    let salt8 = *b"salt0001";
    let key = [7u8; 32];
    let err = emit_fixture(
        1,
        3,
        sample_device_material(&salt8, &key),
        1,
        1,
        Some(1_700_000_000),
    )
    .unwrap_err();
    assert_eq!(err, FixtureError::Reject(RejectReason::UnsupportedFlags));
}

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
        payload: FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            21.5,
        )),
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

    assert_eq!(decoded, fact);
    assert_eq!(validate_fact_binding(&decoded, 0x1234, 7), Ok(()));
    assert_eq!(
        validate_fact_binding(&decoded, 0x5678, 7),
        Err(FramedFactBindingError::PodIdMismatch)
    );
    assert_eq!(
        validate_fact_binding(&decoded, 0x1234, 8),
        Err(FramedFactBindingError::FrameCounterMismatch)
    );
}

#[test]
fn fact_encrypt_decrypt_roundtrip() {
    static KEY: &[u8] = b"frame-test-key";
    let cipher = DummyAead::new(KEY);
    let fact = make_fact(
        PodId::from(5u32),
        1,
        FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            20.0,
        )),
    );

    let nonce = [0u8; AEAD_NONCE_LEN];
    let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
    let dec = decrypt_fact::<128, _>(&cipher, &enc).expect("decrypt fact");

    assert_eq!(fact, dec);
}

#[test]
fn fact_encrypt_decrypt_use_dev_id_msg_type_flags_aad() {
    let cipher = InspectAead::new([0x12, 0x34, 1, 0]);
    let fact = make_fact(
        PodId::from(0x1234u32),
        1,
        FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            20.0,
        )),
    );

    let nonce = [0u8; AEAD_NONCE_LEN];
    let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
    let dec = decrypt_fact::<128, _>(&cipher, &enc).expect("decrypt fact");

    assert_eq!(fact, dec);
}

#[test]
fn fact_serialization_within_max_len() {
    let fact = make_fact(
        PodId::from(99u32),
        12345,
        FactPayload::Env(EnvFact::summary(
            SampleType::AmbientRelativeHumidity,
            1_700_000_000,
            1_700_003_600,
            50.0,
            70.0,
            60.0,
            144,
        )),
    );

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
        FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            20.0,
        )),
    );

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
        FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            20.0,
        )),
    );

    let mut enc =
        encrypt_fact::<128, _>(&cipher, [0u8; AEAD_NONCE_LEN], &fact).expect("encrypt fact");
    if !enc.ciphertext.is_empty() {
        enc.ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_fact::<128, _>(&cipher, &enc);
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

    let result = decrypt_fact::<512, _>(&cipher, &frame);
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
    let restored = ReplayWindow::from_snapshot(state.snapshot("device-101:epoch-1")).unwrap();
    let mut restored = restored;
    assert_eq!(restored.check_and_update(10), Err(RejectReason::Duplicate));
    assert_eq!(restored.check_and_update(8), Err(RejectReason::Duplicate));
}

#[cfg(feature = "xchacha")]
fn sample_frame_and_device() -> (FrameInput<'static>, [u8; 8], [u8; 32]) {
    let key = [7u8; 32];
    let salt8 = *b"salt0001";
    let fact = Fact {
        pod_id: PodId::from(1u32),
        fc: 3,
        ingest_time: 0,
        pod_time: Some(1_700_000_000),
        kind: FactKind::Env,
        payload: FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            21.5,
        )),
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
#[test]
fn validate_and_decrypt_succeeds_for_valid_frame() {
    let (frame, salt8, key) = sample_frame_and_device();
    let accepted = validate_and_decrypt(
        frame,
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
    )
    .expect("postcard fact");

    assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
    assert_eq!(accepted.fact.fc, 3);
    assert_eq!(accepted.fact.kind, FactKind::Env);
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
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
    )
    .unwrap_err();
    assert_eq!(err, RejectReason::UnsupportedFlags);
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
    let err = validate_and_decrypt(
        frame,
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
    )
    .unwrap_err();
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
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
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
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
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
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
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
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
    )
    .expect("fixture decrypt");

    assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
    assert_eq!(accepted.fact.fc, 3);
}

#[cfg(feature = "xchacha")]
#[test]
fn emit_fixture_rejects_nonzero_flags() {
    let salt8 = *b"salt0001";
    let key = [7u8; 32];
    let err = emit_fixture(
        1,
        3,
        DeviceMaterial {
            salt8: &salt8,
            ck_up: &key,
        },
        1,
        1,
        Some(1_700_000_000),
    )
    .unwrap_err();
    assert_eq!(err, FixtureError::Reject(RejectReason::UnsupportedFlags));
}

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use serde_json::{Map, Value, json};

const MAX_FRAME_CIPHERTEXT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameFields {
    dev_id: u16,
    msg_type: u8,
    fc: u32,
    nonce_b64: String,
    ct_b64: String,
    tag_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeviceMaterial {
    salt8_b64: String,
    ck_up_b64: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RejectReason {
    MissingFrameFields,
    InvalidHdr,
    InvalidHdrTypes,
    InvalidFrameTypes,
    InvalidBase64,
    UnknownDevice,
    MissingSalt8,
    Salt8Length,
    CkUpLength,
    NonceLength,
    TagLength,
    EmptyCiphertext,
    CiphertextTooLarge,
    NonceSaltMismatch,
    NonceFcMismatch,
    DecryptFailed,
}

impl RejectReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingFrameFields => "missing_frame_fields",
            Self::InvalidHdr => "invalid_hdr",
            Self::InvalidHdrTypes => "invalid_hdr_types",
            Self::InvalidFrameTypes => "invalid_frame_types",
            Self::InvalidBase64 => "invalid_base64",
            Self::UnknownDevice => "unknown_device",
            Self::MissingSalt8 => "missing_salt8",
            Self::Salt8Length => "salt8_length",
            Self::CkUpLength => "ck_up_length",
            Self::NonceLength => "nonce_length",
            Self::TagLength => "tag_length",
            Self::EmptyCiphertext => "empty_ciphertext",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::NonceSaltMismatch => "nonce_salt_mismatch",
            Self::NonceFcMismatch => "nonce_fc_mismatch",
            Self::DecryptFailed => "decrypt_failed",
        }
    }
}

fn get_required<'py>(
    dict: &Bound<'py, PyDict>,
    key: &str,
    missing: RejectReason,
) -> Result<Bound<'py, PyAny>, RejectReason> {
    dict.get_item(key).map_err(|_| missing)?.ok_or(missing)
}

fn extract_non_bool_u64(
    dict: &Bound<'_, PyDict>,
    key: &str,
    missing: RejectReason,
    invalid: RejectReason,
) -> Result<u64, RejectReason> {
    let value = get_required(dict, key, missing)?;
    if value.is_instance_of::<PyBool>() {
        return Err(invalid);
    }
    value.extract::<u64>().map_err(|_| invalid)
}

fn extract_string(
    dict: &Bound<'_, PyDict>,
    key: &str,
    missing: RejectReason,
    invalid: RejectReason,
) -> Result<String, RejectReason> {
    get_required(dict, key, missing)?
        .extract::<String>()
        .map_err(|_| invalid)
}

fn extract_frame_fields(frame: &Bound<'_, PyAny>) -> Result<FrameFields, RejectReason> {
    let frame_dict = frame
        .cast::<PyDict>()
        .map_err(|_| RejectReason::MissingFrameFields)?;
    let hdr_obj = get_required(frame_dict, "hdr", RejectReason::MissingFrameFields)?;
    let hdr = hdr_obj
        .cast::<PyDict>()
        .map_err(|_| RejectReason::InvalidHdr)?;

    let dev_id = u16::try_from(extract_non_bool_u64(
        hdr,
        "dev_id",
        RejectReason::InvalidHdrTypes,
        RejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| RejectReason::InvalidHdrTypes)?;
    let msg_type = u8::try_from(extract_non_bool_u64(
        hdr,
        "msg_type",
        RejectReason::InvalidHdrTypes,
        RejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| RejectReason::InvalidHdrTypes)?;
    let fc = u32::try_from(extract_non_bool_u64(
        hdr,
        "fc",
        RejectReason::InvalidHdrTypes,
        RejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| RejectReason::InvalidHdrTypes)?;

    Ok(FrameFields {
        dev_id,
        msg_type,
        fc,
        nonce_b64: extract_string(
            frame_dict,
            "nonce",
            RejectReason::MissingFrameFields,
            RejectReason::InvalidFrameTypes,
        )?,
        ct_b64: extract_string(
            frame_dict,
            "ct",
            RejectReason::MissingFrameFields,
            RejectReason::InvalidFrameTypes,
        )?,
        tag_b64: extract_string(
            frame_dict,
            "tag",
            RejectReason::MissingFrameFields,
            RejectReason::InvalidFrameTypes,
        )?,
    })
}

fn extract_device_material(
    device_entry: &Bound<'_, PyAny>,
) -> Result<DeviceMaterial, RejectReason> {
    let entry_dict = device_entry
        .cast::<PyDict>()
        .map_err(|_| RejectReason::UnknownDevice)?;
    Ok(DeviceMaterial {
        salt8_b64: extract_string(
            entry_dict,
            "salt8",
            RejectReason::MissingSalt8,
            RejectReason::InvalidBase64,
        )?,
        ck_up_b64: extract_string(
            entry_dict,
            "ck_up",
            RejectReason::UnknownDevice,
            RejectReason::InvalidBase64,
        )?,
    })
}

fn decode_tlv_payload(data: &[u8]) -> Map<String, Value> {
    let mut index = 0usize;
    let mut out = Map::new();

    while index + 2 <= data.len() {
        let tag = data[index];
        let len = data[index + 1] as usize;
        index += 2;
        if index + len > data.len() {
            break;
        }
        let value = &data[index..index + len];
        index += len;

        match (tag, len) {
            (0x01, 4) => {
                out.insert(
                    "counter".to_string(),
                    json!(u32::from_be_bytes([value[0], value[1], value[2], value[3]])),
                );
            }
            (0x02, 2) => {
                let raw = u16::from_be_bytes([value[0], value[1]]);
                out.insert("bioimpedance".to_string(), json!(f64::from(raw) / 100.0));
            }
            (0x03, 2) => {
                let raw = i16::from_be_bytes([value[0], value[1]]);
                out.insert("temp_c".to_string(), json!(f64::from(raw) / 100.0));
            }
            (0x07, 1) => {
                out.insert("status_flags".to_string(), json!(value[0]));
            }
            _ => {}
        }
    }

    out
}

fn validate_and_decrypt_impl(
    frame: &FrameFields,
    device: &DeviceMaterial,
) -> Result<Map<String, Value>, RejectReason> {
    let nonce = STANDARD
        .decode(frame.nonce_b64.as_bytes())
        .map_err(|_| RejectReason::InvalidBase64)?;
    let ct = STANDARD
        .decode(frame.ct_b64.as_bytes())
        .map_err(|_| RejectReason::InvalidBase64)?;
    let tag = STANDARD
        .decode(frame.tag_b64.as_bytes())
        .map_err(|_| RejectReason::InvalidBase64)?;
    let salt8 = STANDARD
        .decode(device.salt8_b64.as_bytes())
        .map_err(|_| RejectReason::InvalidBase64)?;
    let ck_up = STANDARD
        .decode(device.ck_up_b64.as_bytes())
        .map_err(|_| RejectReason::InvalidBase64)?;

    if nonce.len() != trackone_constants::AEAD_NONCE_LEN {
        return Err(RejectReason::NonceLength);
    }
    if tag.len() != trackone_constants::AEAD_TAG_LEN {
        return Err(RejectReason::TagLength);
    }
    if salt8.len() != 8 {
        return Err(RejectReason::Salt8Length);
    }
    if ck_up.len() != 32 {
        return Err(RejectReason::CkUpLength);
    }
    if ct.is_empty() {
        return Err(RejectReason::EmptyCiphertext);
    }
    if ct.len() > MAX_FRAME_CIPHERTEXT_BYTES {
        return Err(RejectReason::CiphertextTooLarge);
    }
    if nonce[..8] != salt8[..] {
        return Err(RejectReason::NonceSaltMismatch);
    }
    if u64::from_be_bytes(nonce[8..16].try_into().expect("nonce slice length"))
        != u64::from(frame.fc)
    {
        return Err(RejectReason::NonceFcMismatch);
    }

    let aad = [frame.dev_id.to_be_bytes().as_slice(), &[frame.msg_type]].concat();
    let combined = [ct.as_slice(), tag.as_slice()].concat();
    let cipher = XChaCha20Poly1305::new_from_slice(&ck_up).map_err(|_| RejectReason::CkUpLength)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: combined.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| RejectReason::DecryptFailed)?;

    Ok(decode_tlv_payload(&plaintext))
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
fn validate_and_decrypt_framed(
    py: Python<'_>,
    frame: &Bound<'_, PyAny>,
    device_entry: &Bound<'_, PyAny>,
) -> PyResult<(Option<Py<PyDict>>, Option<String>)> {
    let frame_fields = match extract_frame_fields(frame) {
        Ok(value) => value,
        Err(reason) => return Ok((None, Some(reason.as_str().to_string()))),
    };
    let device_material = match extract_device_material(device_entry) {
        Ok(value) => value,
        Err(reason) => return Ok((None, Some(reason.as_str().to_string()))),
    };
    let payload = match validate_and_decrypt_impl(&frame_fields, &device_material) {
        Ok(value) => value,
        Err(reason) => return Ok((None, Some(reason.as_str().to_string()))),
    };

    let payload_dict = PyDict::new(py);
    for (key, value) in payload {
        match value {
            Value::Number(number) if number.is_u64() => {
                payload_dict.set_item(key, number.as_u64().expect("u64 payload"))?;
            }
            Value::Number(number) if number.is_i64() => {
                payload_dict.set_item(key, number.as_i64().expect("i64 payload"))?;
            }
            Value::Number(number) if number.is_f64() => {
                payload_dict.set_item(key, number.as_f64().expect("f64 payload"))?;
            }
            other => {
                payload_dict.set_item(key, other.to_string())?;
            }
        }
    }

    Ok((Some(payload_dict.unbind()), None))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "crypto")?;
    sub.add_function(wrap_pyfunction!(version, &sub)?)?;
    sub.add_function(wrap_pyfunction!(validate_and_decrypt_framed, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_b64(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    fn sample_frame_and_device() -> (FrameFields, DeviceMaterial, Map<String, Value>) {
        let key = [7u8; 32];
        let salt8 = *b"salt0001";
        let fc = 3u32;
        let nonce_tail = *b"rand0001";
        let nonce = [
            salt8.as_slice(),
            &(u64::from(fc)).to_be_bytes(),
            nonce_tail.as_slice(),
        ]
        .concat();
        let aad = [1u16.to_be_bytes().as_slice(), &[1u8]].concat();
        let plaintext = [0x01, 4, 0, 0, 0, 3, 0x03, 2, 0x09, 0xE0];
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
        let combined = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .expect("encrypt");
        let (ct, tag) = combined.split_at(combined.len() - trackone_constants::AEAD_TAG_LEN);

        let mut expected = Map::new();
        expected.insert("counter".to_string(), json!(3u32));
        expected.insert("temp_c".to_string(), json!(25.28));

        (
            FrameFields {
                dev_id: 1,
                msg_type: 1,
                fc,
                nonce_b64: encode_b64(&nonce),
                ct_b64: encode_b64(ct),
                tag_b64: encode_b64(tag),
            },
            DeviceMaterial {
                salt8_b64: encode_b64(&salt8),
                ck_up_b64: encode_b64(&key),
            },
            expected,
        )
    }

    #[test]
    fn validate_and_decrypt_succeeds_for_valid_frame() {
        let (frame, device, expected) = sample_frame_and_device();
        let payload = validate_and_decrypt_impl(&frame, &device).expect("payload");
        assert_eq!(payload, expected);
    }

    #[test]
    fn validate_and_decrypt_rejects_nonce_counter_mismatch() {
        let (mut frame, device, _expected) = sample_frame_and_device();
        let nonce = STANDARD.decode(frame.nonce_b64.as_bytes()).expect("nonce");
        let mut tampered = nonce.clone();
        tampered[15] ^= 0x01;
        frame.nonce_b64 = encode_b64(&tampered);
        let err = validate_and_decrypt_impl(&frame, &device).unwrap_err();
        assert_eq!(err, RejectReason::NonceFcMismatch);
    }

    #[test]
    fn validate_and_decrypt_rejects_oversized_ciphertext() {
        let (mut frame, device, _expected) = sample_frame_and_device();
        frame.ct_b64 = encode_b64(&vec![0u8; MAX_FRAME_CIPHERTEXT_BYTES + 1]);
        let err = validate_and_decrypt_impl(&frame, &device).unwrap_err();
        assert_eq!(err, RejectReason::CiphertextTooLarge);
    }

    #[test]
    fn validate_and_decrypt_rejects_empty_ciphertext() {
        let (mut frame, device, _expected) = sample_frame_and_device();
        frame.ct_b64 = encode_b64(&[]);
        let err = validate_and_decrypt_impl(&frame, &device).unwrap_err();
        assert_eq!(err, RejectReason::EmptyCiphertext);
    }

    #[test]
    fn validate_and_decrypt_rejects_bad_salt_prefix() {
        let (frame, mut device, _expected) = sample_frame_and_device();
        device.salt8_b64 = encode_b64(b"salt9999");
        let err = validate_and_decrypt_impl(&frame, &device).unwrap_err();
        assert_eq!(err, RejectReason::NonceSaltMismatch);
    }

    #[test]
    fn validate_and_decrypt_rejects_decrypt_failure() {
        let (mut frame, device, _expected) = sample_frame_and_device();
        let ct = STANDARD.decode(frame.ct_b64.as_bytes()).expect("ct");
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        frame.ct_b64 = encode_b64(&tampered);
        let err = validate_and_decrypt_impl(&frame, &device).unwrap_err();
        assert_eq!(err, RejectReason::DecryptFailed);
    }

}

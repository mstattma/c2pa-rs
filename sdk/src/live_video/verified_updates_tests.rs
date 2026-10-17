// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Atomic VSI updates on the upstream baseline, without fork-only receiver state.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::{io::Cursor, sync::Arc};

use super::{
    moof_sequence_number,
    test_helpers::{make_mdat_box, make_segment, make_uuid_box},
    Ed25519SessionKey, LiveVideoValidator, LiveVideoVsiSigner,
};
use crate::{
    assertions::SessionKeys,
    settings::{get_thread_local_settings, set_settings_value},
    status_tracker::{ErrorBehavior, StatusTracker},
    utils::{test::test_context, test_signer::test_signer},
    validation_results::{validation_codes, ValidationState},
    Context, Reader, Settings, SigningAlg,
};

const INIT: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s_init.mp4");
const MEDIA_A: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s102.m4s");
const MEDIA_B: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s103.m4s");

fn trusted_context() -> Arc<Context> {
    // Use the fixture chain and a signer with no TSA, not weaker verification.
    let mut context = test_context().with_signer(test_signer(SigningAlg::Es256));
    let settings = context.settings_mut();
    settings.verify.verify_after_reading = true;
    settings.verify.verify_after_sign = true;
    settings.verify.verify_after_sign_hash = true;
    settings.verify.verify_trust = true;
    settings.verify.verify_timestamp_trust = true;
    settings.verify.ocsp_fetch = false;
    settings.verify.remote_manifest_fetch = false;
    settings.builder.certificate_status_fetch = None;
    settings.builder.auto_timestamp_assertion.enabled = false;
    settings.core.allowed_network_hosts = Some(Vec::new());
    assert!(context.signer().unwrap().time_authority_url().is_none());
    context.into_shared()
}

// The baseline producer still uses thread-local Builder/Reader settings internally.
struct ProducerSettings(Settings);

impl ProducerSettings {
    fn new(settings: &Settings) -> Self {
        let guard = Self(get_thread_local_settings());
        Self::configure_trust(settings);
        guard
    }

    fn configure_trust(settings: &Settings) {
        let values = serde_json::to_value(settings).unwrap();
        for name in ["core", "trust", "verify", "builder"] {
            set_settings_value(name, values[name].clone()).unwrap();
        }
    }
}

impl Drop for ProducerSettings {
    fn drop(&mut self) {
        Self::configure_trust(&self.0);
        assert_eq!(get_thread_local_settings(), self.0);
    }
}

fn make_producer(context: &Context, seed: u8, kid: &[u8]) -> LiveVideoVsiSigner {
    LiveVideoVsiSigner::from_signing_key(
        r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        context.signer().unwrap(),
        Ed25519SessionKey::from_bytes(&[seed; 32]),
        kid.to_vec(),
        u64::from(moof_sequence_number(MEDIA_A).unwrap()),
        3600,
    )
    .unwrap()
}

fn read_init(context: &Arc<Context>, init: &[u8]) -> Reader {
    Reader::from_shared_context(context)
        .with_stream("video/mp4", Cursor::new(init))
        .unwrap()
}

fn verified_init_material(reader: &Reader) -> Option<(SessionKeys, String, Vec<u8>)> {
    if reader.validation_state() != ValidationState::Trusted {
        return None;
    }
    if !reader
        .validation_results()
        .unwrap()
        .active_manifest()
        .unwrap()
        .failure()
        .is_empty()
    {
        return None;
    }
    let manifest = reader.active_manifest().unwrap();
    let keys = manifest.find_assertion(SessionKeys::LABEL).unwrap();
    let label = manifest.label().unwrap().to_string();
    let certs = pem::parse_many(manifest.signature_info().unwrap().cert_chain()).unwrap();
    let leaf = certs.into_iter().next().unwrap().into_contents();
    Some((keys, label, leaf))
}

fn initialized_receiver(
    init: &[u8],
    reader: &Reader,
    behavior: &ErrorBehavior,
) -> (LiveVideoValidator, StatusTracker) {
    let (keys, label, leaf) = verified_init_material(reader).unwrap();
    let mut receiver = LiveVideoValidator::new();
    let mut tracker = StatusTracker::with_error_behavior(match behavior {
        ErrorBehavior::ContinueWhenPossible => ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError => ErrorBehavior::StopOnFirstError,
    });
    receiver.validate_init_segment(init, &mut tracker).unwrap();
    receiver
        .validate_session_keys(&keys, &label, Some(&leaf), &mut tracker)
        .unwrap();
    assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
    (receiver, tracker)
}

fn assert_media_accepted(
    receiver: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
    media: &[u8],
    label: &str,
) {
    let failures_before = tracker.filter_errors().count();
    receiver
        .validate_verifiable_segment_info(media, tracker)
        .unwrap();
    assert_eq!(
        tracker.filter_errors().count(),
        failures_before,
        "{tracker:?}"
    );
    let previous = receiver.previous_segment.as_ref().unwrap();
    assert_eq!(
        previous.sequence_number,
        u64::from(moof_sequence_number(media).unwrap())
    );
    assert_eq!(previous.manifest_id, label);
    assert!(previous.stream_id.is_empty());
    assert_eq!(receiver.expected_manifest_id.as_deref(), Some(label));
    assert!(!receiver.manifest_box_context);
}

#[test]
fn reader_trusted_a_to_b_update_preserves_existing_sequence_baseline() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        assert_eq!(
            moof_sequence_number(MEDIA_B).unwrap(),
            moof_sequence_number(MEDIA_A).unwrap() + 1
        );
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut producer = make_producer(&context, 0x42, b"session-a");
        let init_a = producer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, label_a, leaf_a) = verified_init_material(&reader_a).unwrap();
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, &behavior);
        let media_a = producer.sign_media_segment(MEDIA_A).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_a, &label_a);

        // Re-sign on the same producer, keeping its next media sequence number.
        let next_sequence = producer.next_sequence_number();
        let init_b = producer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        assert_eq!(producer.next_sequence_number(), next_sequence);
        let reader_b = read_init(&context, &init_b);
        let (keys_b, label_b, leaf_b) = verified_init_material(&reader_b).unwrap();
        assert_ne!(label_a, label_b);
        assert_eq!(keys_a, keys_b);
        assert_eq!(leaf_a, leaf_b);
        receiver
            .update_vsi_context(
                Some(&init_b),
                &keys_b,
                &label_b,
                Some(&leaf_b),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
        assert_eq!(receiver.session_keys, keys_b.keys);
        assert_eq!(
            receiver.expected_manifest_id.as_deref(),
            Some(label_b.as_str())
        );
        let previous = receiver.previous_segment.as_ref().unwrap();
        assert_eq!(previous.manifest_id, label_a);
        assert!(previous.stream_id.is_empty());
        assert_eq!(previous.sequence_number, next_sequence - 1);

        // A duplicate sequence is still rejected after the update. Keep its diagnostic
        // to also exercise successful media validation with a prior tracker failure.
        let mut duplicate = make_producer(&context, 0x42, b"session-a");
        duplicate
            .restore_manifest_id_from_signed_init(&init_b, "video/mp4")
            .unwrap();
        let duplicate_media = duplicate.sign_media_segment(MEDIA_A).unwrap();
        let result = receiver.validate_verifiable_segment_info(&duplicate_media, &mut tracker);
        assert_eq!(result.is_err(), behavior == ErrorBehavior::StopOnFirstError);
        assert_eq!(tracker.filter_errors().count(), 1, "{tracker:?}");
        assert!(tracker.has_status(validation_codes::LIVEVIDEO_ASSERTION_INVALID));
        assert_eq!(
            receiver.previous_segment.as_ref().unwrap().manifest_id,
            label_a
        );
        assert_eq!(
            receiver.previous_segment.as_ref().unwrap().sequence_number,
            next_sequence - 1
        );

        let media_b = producer.sign_media_segment(MEDIA_B).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_b, &label_b);
    }
}

#[test]
fn rejected_candidates_are_atomic_and_old_media_remains_usable() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut producer_a = make_producer(&context, 0x42, b"session-a");
        let init_a = producer_a
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, label_a, _) = verified_init_material(&reader_a).unwrap();
        let media_a = producer_a.sign_media_segment(MEDIA_A).unwrap();
        let next_a = producer_a.sign_media_segment(MEDIA_B).unwrap();
        let mut producer_b = make_producer(&context, 0x43, b"session-b");
        let init_b = producer_b
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let (keys_b, label_b, leaf_b) =
            verified_init_material(&read_init(&context, &init_b)).unwrap();
        let mdat = make_mdat_box();

        for case in [
            "bad-binding",
            "valid-then-bad-binding",
            "bad-binding-then-valid",
            "valid-then-zero-period",
            "empty-keys",
            "missing-cert",
            "wrong-cert",
            "empty-manifest-id",
            "missing-kid",
            "empty-kid",
            "duplicate-kid",
            "init-with-mdat",
        ] {
            let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, &behavior);
            assert_media_accepted(&mut receiver, &mut tracker, &media_a, &label_a);
            let mut candidate = keys_b.clone();
            let mut manifest_id = label_b.as_str();
            let mut cert = Some(leaf_b.as_slice());
            let mut init = None;
            match case {
                "bad-binding" => candidate.keys[0].signer_binding = c2pa_cbor::Value::Null,
                "valid-then-bad-binding" | "bad-binding-then-valid" => {
                    candidate.keys.push(keys_a.keys[0].clone());
                    let bad_index = usize::from(case == "valid-then-bad-binding");
                    candidate.keys[bad_index].signer_binding = c2pa_cbor::Value::Null;
                }
                "valid-then-zero-period" => {
                    candidate.keys.push(keys_a.keys[0].clone());
                    candidate.keys[1].validity_period = 0;
                }
                "empty-keys" => candidate.keys.clear(),
                "missing-cert" => cert = None,
                "wrong-cert" => cert = Some(b"not-the-verified-leaf"),
                "empty-manifest-id" => manifest_id = "",
                "missing-kid" | "empty-kid" => {
                    let c2pa_cbor::Value::Map(map) = &mut candidate.keys[0].key else {
                        unreachable!();
                    };
                    // Match production's integer coercion, including Reader's text labels.
                    map.retain(|label, _| {
                        let number = match label {
                            c2pa_cbor::Value::Integer(n) => Some(i128::from(*n)),
                            c2pa_cbor::Value::Text(s) => s.parse::<i128>().ok(),
                            _ => None,
                        };
                        number != Some(2)
                    });
                    if case == "empty-kid" {
                        map.insert(
                            c2pa_cbor::Value::Integer(2),
                            c2pa_cbor::Value::Bytes(Vec::new()),
                        );
                    }
                    assert_eq!(
                        super::cose_key::kid_from_cose_key(&candidate.keys[0].key),
                        if case == "missing-kid" {
                            None
                        } else {
                            Some(Vec::new())
                        },
                    );
                }
                "duplicate-kid" => candidate.keys.push(candidate.keys[0].clone()),
                "init-with-mdat" => init = Some(mdat.as_slice()),
                _ => unreachable!(),
            }
            assert!(
                receiver
                    .update_vsi_context(init, &candidate, manifest_id, cert, &mut tracker)
                    .is_err(),
                "{case}"
            );
            assert!(tracker.filter_errors().count() > 0, "{case}: {tracker:?}");
            assert_eq!(receiver.session_keys, keys_a.keys, "{case}");
            assert_eq!(
                receiver.expected_manifest_id.as_deref(),
                Some(label_a.as_str())
            );
            let previous = receiver.previous_segment.as_ref().unwrap();
            assert_eq!(previous.manifest_id, label_a);
            assert!(previous.stream_id.is_empty());
            assert_eq!(
                previous.sequence_number,
                u64::from(moof_sequence_number(MEDIA_A).unwrap())
            );
            assert_media_accepted(&mut receiver, &mut tracker, &next_a, &label_a);
        }
    }
}

#[test]
fn all_valid_keys_install_despite_prior_diagnostics_without_an_init() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut producer_a = make_producer(&context, 0x42, b"session-a");
        let init_a = producer_a
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, _, _) = verified_init_material(&reader_a).unwrap();
        let mut producer_b = make_producer(&context, 0x43, b"session-b");
        let init_b = producer_b
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let (mut keys_b, label_b, leaf_b) =
            verified_init_material(&read_init(&context, &init_b)).unwrap();
        // Raw-API unit case: combine independently bound keys, not a Reader trust claim
        // about this synthetic two-key assertion.
        keys_b.keys.push(keys_a.keys[0].clone());
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, &behavior);
        let _ = receiver.fail_init_manifest("earlier unrelated failure", &mut tracker);
        let failures_before = tracker.filter_errors().count();
        assert_eq!(failures_before, 1);
        receiver
            .update_vsi_context(None, &keys_b, &label_b, Some(&leaf_b), &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), failures_before);
        assert_eq!(receiver.session_keys, keys_b.keys);
        assert_eq!(
            receiver.expected_manifest_id.as_deref(),
            Some(label_b.as_str())
        );
        assert!(receiver.previous_segment.is_none());
        let media_b = producer_b.sign_media_segment(MEDIA_A).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_b, &label_b);
        producer_a
            .restore_manifest_id_from_signed_init(&init_b, "video/mp4")
            .unwrap();
        producer_a.sign_media_segment(MEDIA_A).unwrap();
        let next = producer_a.sign_media_segment(MEDIA_B).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &next, &label_b);
    }
}

#[test]
fn update_requires_existing_vsi_context_and_rejects_manifest_box_context() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut producer = make_producer(&context, 0x42, b"session-a");
        let init = producer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let reader = read_init(&context, &init);
        let (keys, label, leaf) = verified_init_material(&reader).unwrap();
        for case in ["fresh", "no-expected-id", "no-keys", "manifest-box"] {
            let (mut receiver, mut tracker) = initialized_receiver(&init, &reader, &behavior);
            match case {
                "fresh" => receiver = LiveVideoValidator::new(),
                "no-expected-id" => receiver.expected_manifest_id = None,
                "no-keys" => receiver.session_keys.clear(),
                "manifest-box" => {
                    receiver
                        .validate_media_segment(
                            &make_uuid_box(true),
                            "manifest-box-a",
                            &make_segment(10, "stream-a"),
                            &mut tracker,
                        )
                        .unwrap();
                    assert!(receiver.manifest_box_context);
                }
                _ => unreachable!(),
            }
            assert_eq!(tracker.filter_errors().count(), 0);
            let old_keys = receiver.session_keys.clone();
            let old_id = receiver.expected_manifest_id.clone();
            assert!(receiver
                .update_vsi_context(Some(&init), &keys, &label, Some(&leaf), &mut tracker)
                .is_err());
            assert_eq!(receiver.session_keys, old_keys);
            assert_eq!(receiver.expected_manifest_id, old_id);
            assert_eq!(tracker.filter_errors().count(), 1);
            if case == "manifest-box" {
                let previous = receiver.previous_segment.as_ref().unwrap();
                assert_eq!(previous.sequence_number, 10);
                assert_eq!(previous.stream_id, "stream-a");
                assert_eq!(previous.manifest_id, "manifest-box-a");
                assert!(receiver.manifest_box_context);
            } else {
                assert!(receiver.previous_segment.is_none());
                assert!(!receiver.manifest_box_context);
            }
        }
    }
}

#[test]
fn reader_trust_and_init_hard_binding_are_caller_update_gates() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut producer = make_producer(&context, 0x42, b"session-a");
        let init_a = producer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, label_a, _) = verified_init_material(&reader_a).unwrap();
        let media_a = producer.sign_media_segment(MEDIA_A).unwrap();
        let next_a = producer.sign_media_segment(MEDIA_B).unwrap();
        let init_b = producer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let (_, label_b, _) = verified_init_material(&read_init(&context, &init_b)).unwrap();
        assert_ne!(label_a, label_b);

        let mut anchorless = test_context();
        *anchorless.settings_mut() = context.settings().clone();
        anchorless.settings_mut().trust.anchors = Some(Vec::new());
        assert!(anchorless.settings().verify.verify_trust);
        assert!(anchorless.settings().verify.verify_after_reading);
        let untrusted = read_init(&anchorless.into_shared(), &init_b);
        assert_ne!(untrusted.validation_state(), ValidationState::Trusted);
        assert!(untrusted
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure()
            .iter()
            .any(|status| status.code() == validation_codes::SIGNING_CREDENTIAL_UNTRUSTED));

        // Change the version-0 mvhd playback rate outside the C2PA exclusions.
        let mut tampered_init = init_b.clone();
        let mvhd = tampered_init
            .windows(4)
            .position(|bytes| bytes == b"mvhd")
            .unwrap();
        assert_eq!(tampered_init[mvhd + 4], 0);
        tampered_init[mvhd + 27] ^= 1;
        let tampered = read_init(&context, &tampered_init);
        assert_eq!(tampered.validation_state(), ValidationState::Invalid);
        assert!(tampered
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure()
            .iter()
            .any(|status| status.code() == validation_codes::ASSERTION_BMFFHASH_MISMATCH));

        for reader in [&untrusted, &tampered] {
            let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, &behavior);
            assert_media_accepted(&mut receiver, &mut tracker, &media_a, &label_a);
            // The raw update API cannot enforce this Reader gate on the caller's behalf.
            assert!(verified_init_material(reader).is_none());
            if let Some((keys, label, leaf)) = verified_init_material(reader) {
                receiver
                    .update_vsi_context(None, &keys, &label, Some(&leaf), &mut tracker)
                    .unwrap();
            }
            assert_eq!(receiver.session_keys, keys_a.keys);
            assert_eq!(
                receiver.expected_manifest_id.as_deref(),
                Some(label_a.as_str())
            );
            assert_media_accepted(&mut receiver, &mut tracker, &next_a, &label_a);
        }
    }
}

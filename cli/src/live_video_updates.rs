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

use std::{
    collections::HashSet,
    fs::File,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use c2pa::{
    assertions::SessionKeys, format_from_path, live_video::LiveVideoValidator,
    status_tracker::StatusTracker, Context as C2paContext, Reader, ValidationState,
};
use serde::Deserialize;

const MAX_SCHEDULE_BYTES: u64 = 1024 * 1024;
const MAX_UPDATES: usize = 1024;
const MAX_INIT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    version: u32,
    updates: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    before_segment: String,
    init: PathBuf,
}

pub(super) struct Update {
    pub segment_index: usize,
    pub init_path: PathBuf,
    snapshot: Result<Snapshot>,
}

struct Snapshot {
    init_data: Vec<u8>,
    verified: VerifiedContext,
}

struct VerifiedContext {
    session_keys: SessionKeys,
    manifest_id: String,
    ee_cert_der: Vec<u8>,
}

pub(super) fn require_verification(context: &C2paContext) -> Result<()> {
    let settings = context.settings();
    if !settings.get_value::<bool>("verify.verify_after_reading")?
        || !settings.get_value::<bool>("verify.verify_trust")?
    {
        bail!("--updates requires verify_after_reading and verify_trust enabled");
    }
    Ok(())
}

fn reader_context(context: &C2paContext) -> Result<Arc<C2paContext>> {
    let settings = context
        .settings()
        .clone()
        .with_value("verify.remote_manifest_fetch", false)?;
    Ok(Arc::new(C2paContext::new().with_settings(settings)?))
}

fn read_snapshot(path: &Path, max_bytes: u64, remaining: &mut u64) -> Result<Vec<u8>> {
    let limit = max_bytes.min(*remaining);
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Cannot read VSI init snapshot: {path:?}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("VSI init snapshot exceeds available raw-byte limit ({limit} bytes): {path:?}");
    }
    *remaining -= bytes.len() as u64;
    Ok(bytes)
}

fn capture_context(
    context: &Arc<C2paContext>,
    init_path: &Path,
    remaining: &mut u64,
) -> Result<Snapshot> {
    let init_data = read_snapshot(init_path, MAX_INIT_BYTES, remaining)?;
    let verified = read_context(context, init_path, &init_data)?;
    Ok(Snapshot {
        init_data,
        verified,
    })
}

fn read_context(
    context: &Arc<C2paContext>,
    init_path: &Path,
    init_data: &[u8],
) -> Result<VerifiedContext> {
    require_verification(context)?;
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());
    // Disable asset-directed fetches before the Reader can inspect any untrusted bytes.
    let reader_context = reader_context(context)?;
    let reader = Reader::from_shared_context(&reader_context)
        .with_stream(&format, Cursor::new(init_data))
        .with_context(|| format!("Cannot verify signed VSI init: {init_path:?}"))?;
    let active = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .context("--updates requires active manifest validation results")?;
    if reader.validation_state() != ValidationState::Trusted || !active.failure().is_empty() {
        bail!("--updates requires a Trusted init with no active manifest failures: {init_path:?}");
    }
    if !reader.is_embedded() {
        bail!("--updates requires an embedded signed init manifest: {init_path:?}");
    }
    // All installation material comes from this exact verified Reader, including v1 labels.
    let manifest = reader
        .active_manifest()
        .context("VSI init has no active manifest")?;
    let session_keys = manifest
        .find_assertion::<SessionKeys>(SessionKeys::LABEL)
        .context("--updates supports only VSI signed init assets, not manifest-box streams")?;
    let manifest_id = manifest
        .label()
        .filter(|id| !id.is_empty())
        .context("VSI init manifest label must be nonempty")?
        .to_string();
    let ee_cert_der = super::extract_ee_cert_der(manifest)
        .context("VSI init manifest has no readable leaf certificate")?;
    Ok(VerifiedContext {
        session_keys,
        manifest_id,
        ee_cert_der,
    })
}

fn references(path: &Path, segments: &[PathBuf]) -> Result<Vec<(usize, PathBuf)>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Cannot read VSI update schedule: {path:?}"))?
        .take(MAX_SCHEDULE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SCHEDULE_BYTES {
        bail!("VSI update schedule exceeds 1 MiB");
    }
    // Derived struct deserializers can also accept positional arrays. Require JSON objects,
    // then deserialize the original bytes so duplicate fields still fail rather than collapse.
    let shape: serde_json::Value =
        serde_json::from_slice(&bytes).context("Invalid VSI update schedule")?;
    if !shape.is_object()
        || shape
            .get("updates")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|updates| updates.iter().any(|event| !event.is_object()))
    {
        bail!("VSI update schedule and its events must be JSON objects");
    }
    let schedule: Schedule =
        serde_json::from_slice(&bytes).context("Invalid VSI update schedule")?;
    if schedule.version != 1 {
        bail!("VSI update schedule version must be 1");
    }
    if schedule.updates.len() > MAX_UPDATES {
        bail!("VSI update schedule exceeds 1024 events");
    }
    let mut seen = HashSet::new();
    let mut plan = Vec::new();
    for event in schedule.updates {
        let name = &event.before_segment;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':', '\0']) {
            bail!("before_segment must be a single filename: {name:?}");
        }
        if !seen.insert(name.clone()) {
            bail!("Duplicate VSI update target: {name:?}");
        }
        let mut matches = segments.iter().enumerate().filter(|(_, segment)| {
            segment.file_name().and_then(|name| name.to_str()) == Some(name.as_str())
        });
        let (segment_index, _) = matches.next().with_context(|| {
            format!("VSI update target does not match any selected media segment: {name:?}")
        })?;
        if matches.next().is_some() {
            bail!("Ambiguous VSI update target among selected media segments: {name:?}");
        }
        if event.init.as_os_str().is_empty() {
            bail!("VSI update init path must not be empty");
        }
        plan.push((
            segment_index,
            path.parent().unwrap_or(Path::new(".")).join(event.init),
        ));
    }
    plan.sort_by_key(|(index, _)| *index);
    Ok(plan)
}

pub(super) fn load_plan(
    context: &Arc<C2paContext>,
    path: &Path,
    segments: &[PathBuf],
) -> Result<Vec<Update>> {
    load_plan_with_budget(context, path, segments, MAX_PLAN_BYTES)
}

fn load_plan_with_budget(
    context: &Arc<C2paContext>,
    path: &Path,
    segments: &[PathBuf],
    mut remaining: u64,
) -> Result<Vec<Update>> {
    let mut plan = Vec::new();
    for (segment_index, init_path) in references(path, segments)? {
        let snapshot = capture_context(context, &init_path, &mut remaining);
        let failed = snapshot.is_err();
        plan.push(Update {
            segment_index,
            init_path,
            snapshot,
        });
        // Preserve asset failures for the timeline's JSON report, but stop reading ahead.
        if failed {
            break;
        }
    }
    Ok(plan)
}

impl Update {
    pub(super) fn install(
        &self,
        validator: &mut LiveVideoValidator,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        install_snapshot(&self.snapshot, &self.init_path, validator, tracker, true)
    }
}

/// Only the initial call uses legacy setup; every update uses the same validator atomically.
pub(super) fn install_context(
    context: &Arc<C2paContext>,
    init_path: &Path,
    validator: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
    updating: bool,
) -> Result<()> {
    // The initial init has its own per-file allowance, separate from scheduled snapshots.
    let mut remaining = MAX_INIT_BYTES;
    let snapshot = capture_context(context, init_path, &mut remaining);
    install_snapshot(&snapshot, init_path, validator, tracker, updating)
}

fn install_snapshot(
    snapshot: &Result<Snapshot>,
    init_path: &Path,
    validator: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
    updating: bool,
) -> Result<()> {
    let failures_before = tracker.filter_errors().count();
    let result = (|| -> Result<()> {
        let snapshot = snapshot
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
        let verified = &snapshot.verified;
        if updating {
            validator.update_vsi_context(
                Some(&snapshot.init_data),
                &verified.session_keys,
                &verified.manifest_id,
                Some(&verified.ee_cert_der),
                tracker,
            )?;
        } else {
            validator.validate_init_segment(&snapshot.init_data, tracker)?;
            validator.validate_session_keys(
                &verified.session_keys,
                &verified.manifest_id,
                Some(&verified.ee_cert_der),
                tracker,
            )?;
        }
        if tracker.filter_errors().count() != failures_before {
            bail!("VSI init validation recorded a failure: {init_path:?}");
        }
        Ok(())
    })();
    if let Err(error) = &result {
        if tracker.filter_errors().count() == failures_before {
            // Asset read/Reader errors must also appear in the standard JSON failure array.
            let _ =
                validator.fail_init_manifest(format!("VSI init {init_path:?}: {error:#}"), tracker);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::fs;

    use c2pa::{
        live_video::{Ed25519SessionKey, LiveVideoVsiSigner},
        settings::Settings,
        SigningAlg,
    };
    use clap::Parser;
    use serde_json::{json, Value};
    use tempfile::TempDir;

    use super::*;

    const INIT: &[u8] = include_bytes!("../tests/fixtures/live_video/init.mp4");
    const MANIFEST: &str = r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#;

    fn schedule(dir: &TempDir, value: Value) -> PathBuf {
        let path = dir.path().join("updates.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    fn event(name: &str, init: &Path) -> Value {
        json!({"before_segment": name, "init": init})
    }

    #[test]
    fn update_reader_disables_only_remote_manifest_fetch() {
        let trusted = trusted_context();
        for ocsp_fetch in [false, true] {
            let settings = trusted
                .settings()
                .with_value("verify.remote_manifest_fetch", true)
                .unwrap()
                .with_value("verify.ocsp_fetch", ocsp_fetch)
                .unwrap()
                .with_value("verify.verify_after_sign_hash", ocsp_fetch)
                .unwrap();
            let context = C2paContext::new().with_settings(settings.clone()).unwrap();
            let isolated = reader_context(&context).unwrap();
            assert_eq!(
                isolated.settings(),
                &settings
                    .with_value("verify.remote_manifest_fetch", false)
                    .unwrap()
            );
            assert_eq!(context.settings(), &settings);
            assert!(context
                .settings()
                .get_value::<bool>("verify.remote_manifest_fetch")
                .unwrap());
        }
    }

    #[test]
    fn snapshot_limits_are_inclusive_and_share_remaining_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.mp4");
        fs::write(&path, b"12345").unwrap();
        let mut remaining = 7;
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        assert_eq!(remaining, 7);
        fs::write(&path, b"1234").unwrap();
        assert_eq!(read_snapshot(&path, 4, &mut remaining).unwrap(), b"1234");
        assert_eq!(remaining, 3);
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        assert_eq!(remaining, 3);
        fs::write(&path, b"123").unwrap();
        assert_eq!(read_snapshot(&path, 4, &mut remaining).unwrap(), b"123");
        assert_eq!(remaining, 0);
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        fs::write(&path, b"").unwrap();
        assert!(read_snapshot(&path, 4, &mut remaining).unwrap().is_empty());
    }

    #[test]
    fn updates_flag_is_optional_and_scoped_to_live_video() {
        for updates in [None, Some("updates.json")] {
            let mut args = vec![
                "c2patool",
                "init.mp4",
                "live-video",
                "--segments_glob",
                "seg*.m4s",
            ];
            if let Some(path) = updates {
                args.extend(["--updates", path]);
            }
            let args = crate::CliArgs::try_parse_from(args).unwrap();
            match args.command.unwrap() {
                crate::Commands::LiveVideo {
                    updates: actual, ..
                } => {
                    assert_eq!(actual.as_deref(), updates.map(Path::new));
                }
                _ => panic!("expected live-video"),
            }
        }
        assert!(crate::CliArgs::try_parse_from([
            "c2patool",
            "init.mp4",
            "--updates",
            "updates.json",
        ])
        .is_err());
    }

    #[test]
    fn schema_version_and_fields_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let selected = vec![PathBuf::from("seg103.m4s")];
        for value in [
            json!([1, []]),
            json!({"version": 0, "updates": []}),
            json!({"version": 2, "updates": []}),
            json!({"version": "1", "updates": []}),
            json!({"version": 1, "updates": [], "extra": true}),
            json!({"updates": []}),
            json!({"version": 1}),
            json!({"version": 1, "updates": null}),
            json!({"version": 1, "updates": [["seg103.m4s", "b.mp4"]]}),
            json!({"version": 1, "updates": [{"before_segment": "seg103.m4s"}]}),
            json!({"version": 1, "updates": [{"before_segment": "seg103.m4s", "init": "b.mp4", "extra": true}]}),
        ] {
            assert!(references(&schedule(&dir, value), &selected).is_err());
        }
        let path = dir.path().join("updates.json");
        for bytes in [
            r#"{"version":1,"version":1,"updates":[]}"#,
            r#"{"version":1,"updates":[{"before_segment":"seg103.m4s","init":"b.mp4","init":"c.mp4"}]}"#,
            r#"{"version":1,"updates":[]} trailing"#,
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(references(&path, &selected).is_err());
        }
        assert!(references(&schedule(&dir, json!({"version": 1, "updates": []})), &[]).is_ok());
    }

    #[test]
    fn byte_and_event_limits_are_inclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = schedule(&dir, json!({"version": 1, "updates": []}));
        let mut bytes = fs::read(&path).unwrap();
        bytes.resize(MAX_SCHEDULE_BYTES as usize, b' ');
        fs::write(&path, &bytes).unwrap();
        assert!(references(&path, &[]).is_ok());
        bytes.push(b' ');
        fs::write(&path, bytes).unwrap();
        assert!(references(&path, &[])
            .unwrap_err()
            .to_string()
            .contains("1 MiB"));
        let selected: Vec<_> = (0..=MAX_UPDATES)
            .map(|index| PathBuf::from(format!("seg{index}.m4s")))
            .collect();
        let events: Vec<_> = selected
            .iter()
            .map(|path| event(path.to_str().unwrap(), Path::new("init.mp4")))
            .collect();
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": &events[..MAX_UPDATES]}),
        );
        assert_eq!(references(&path, &selected).unwrap().len(), MAX_UPDATES);
        let path = schedule(&dir, json!({"version": 1, "updates": events}));
        assert!(references(&path, &selected)
            .unwrap_err()
            .to_string()
            .contains("1024"));
    }

    #[test]
    fn targets_are_unique_exact_selected_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let selected = vec![PathBuf::from("media/seg103.m4s")];
        for name in [
            "",
            ".",
            "..",
            "./seg103.m4s",
            "../seg103.m4s",
            "media/seg103.m4s",
            "media\\seg103.m4s",
            "C:seg103.m4s",
            "seg104.m4s",
            "SEG103.m4s",
            "seg*.m4s",
            "seg\0.m4s",
        ] {
            let path = schedule(
                &dir,
                json!({"version": 1, "updates": [event(name, Path::new("b.mp4"))]}),
            );
            assert!(references(&path, &selected).is_err(), "accepted {:?}", name);
        }
        let update = event("seg103.m4s", Path::new("b.mp4"));
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [update.clone(), update.clone()]}),
        );
        assert!(references(&path, &selected)
            .unwrap_err()
            .to_string()
            .contains("Duplicate"));
        let path = schedule(&dir, json!({"version": 1, "updates": [update]}));
        let ambiguous = vec![selected[0].clone(), PathBuf::from("other/seg103.m4s")];
        assert!(references(&path, &ambiguous)
            .unwrap_err()
            .to_string()
            .contains("Ambiguous"));
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [event("seg103.m4s", Path::new(""))]}),
        );
        assert!(references(&path, &selected).is_err());
    }

    #[test]
    fn init_paths_resolve_from_schedule_and_events_follow_media_order() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = dir.path().join("init-c.mp4");
        let selected = vec![PathBuf::from("seg2.m4s"), PathBuf::from("seg10.m4s")];
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg10.m4s", &absolute), event("seg2.m4s", Path::new("../init-b.mp4")),
            ]}),
        );
        let plan = references(&path, &selected).unwrap();
        assert_eq!(plan[0].0, 0);
        assert_eq!(plan[0].1, dir.path().join("../init-b.mp4"));
        assert_eq!(plan[1].0, 1);
        assert_eq!(plan[1].1, absolute);
        // Plan parsing checks references, not asset availability or trust.
        assert!(!plan[0].1.exists());
    }

    fn trusted_context() -> Arc<C2paContext> {
        let settings = Settings::new()
            .with_toml(include_str!("../tests/fixtures/trust/cawg_test_settings.toml")).unwrap()
            .with_json(r#"{
                "core":{"allowed_network_hosts":[]},
                "verify":{"verify_after_reading":true,"verify_after_sign":true,
                    "verify_after_sign_hash":true,"verify_trust":true,
                    "verify_timestamp_trust":true,"ocsp_fetch":false,"remote_manifest_fetch":false},
                "builder":{"certificate_status_fetch":null,"auto_timestamp_assertion":{"enabled":false}}
            }"#).unwrap();
        let signer = c2pa::create_signer::from_keys(
            include_bytes!("../sample/es256_certs.pem"),
            include_bytes!("../sample/es256_private.key"),
            SigningAlg::Es256,
            None,
        )
        .unwrap();
        assert!(signer.time_authority_url().is_none());
        Arc::new(
            C2paContext::new()
                .with_settings(settings)
                .unwrap()
                .with_signer(signer),
        )
    }

    // Public legacy TLS access is needed only for the baseline producer's internal Reader.
    struct ProducerSettings(Settings);

    #[allow(deprecated)]
    impl ProducerSettings {
        fn new(settings: &Settings) -> Self {
            let guard = Self(Settings::from_string("{}", "json").unwrap());
            Self::set(settings);
            guard
        }

        fn set(settings: &Settings) {
            let values = serde_json::to_value(settings).unwrap();
            let overlay = json!({
                "trust": values["trust"],
                "verify": values["verify"],
                "core": {"allowed_network_hosts": values["core"]["allowed_network_hosts"]},
                "builder": {
                    "certificate_status_fetch": values["builder"]["certificate_status_fetch"],
                    "auto_timestamp_assertion": {"enabled": values["builder"]["auto_timestamp_assertion"]["enabled"]},
                },
            });
            Settings::from_string(&overlay.to_string(), "json").unwrap();
        }
    }

    impl Drop for ProducerSettings {
        #[allow(deprecated)]
        fn drop(&mut self) {
            Self::set(&self.0);
            assert_eq!(Settings::from_string("{}", "json").unwrap(), self.0);
        }
    }

    fn producer(context: &C2paContext, minimum: u64, validity: u64) -> LiveVideoVsiSigner {
        LiveVideoVsiSigner::from_signing_key(
            MANIFEST,
            context.signer().unwrap(),
            Ed25519SessionKey::from_bytes(&[0x42; 32]),
            b"session-key".to_vec(),
            minimum,
            validity,
        )
        .unwrap()
    }

    fn make_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(fourcc);
        bytes.extend_from_slice(payload);
        bytes
    }

    // Minimal moof/mfhd + mdat for the upstream sequence/hash checks, not a decodable track.
    fn media(sequence: u32) -> Vec<u8> {
        let mut header = vec![0; 4];
        header.extend_from_slice(&sequence.to_be_bytes());
        let mut bytes = make_box(b"moof", &make_box(b"mfhd", &header));
        bytes.extend(make_box(b"mdat", &[0; 16]));
        bytes
    }

    fn signed_corpus(validity_b: u64) -> (TempDir, Arc<C2paContext>, PathBuf) {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let dir = tempfile::tempdir().unwrap();
        let mut a = producer(&context, 102, 3600);
        let init_a = a
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        fs::write(
            dir.path().join("seg102.m4s"),
            a.sign_media_segment(&media(102)).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.path().join("old103.m4s"),
            a.sign_media_segment(&media(103)).unwrap(),
        )
        .unwrap();
        let mut b = producer(&context, 102, validity_b);
        let init_b = b
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        fs::write(
            dir.path().join("equal102.m4s"),
            b.sign_media_segment(&media(102)).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.path().join("seg103.m4s"),
            b.sign_media_segment(&media(103)).unwrap(),
        )
        .unwrap();
        fs::write(dir.path().join("init-a.mp4"), init_a).unwrap();
        fs::write(dir.path().join("init-b.mp4"), init_b).unwrap();
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg103.m4s", Path::new("init-b.mp4")),
            ]}),
        );
        (dir, context, path)
    }

    fn timeline(
        dir: &TempDir,
        context: &Arc<C2paContext>,
        path: &Path,
    ) -> super::super::LiveVideoReport {
        let init = dir.path().join("init-a.mp4");
        let selected = super::super::collect_segments(&init, Path::new("seg*.m4s")).unwrap();
        let plan = load_plan(context, path, &selected).unwrap();
        super::super::validate_update_timeline(context, &init, &selected, &plan)
    }

    #[test]
    fn retained_snapshots_share_budget_and_limit_failures_keep_json_reporting() {
        let (dir, context, _) = signed_corpus(3600);
        let init = dir.path().join("init-a.mp4");
        let b = dir.path().join("init-b.mp4");
        let size = fs::metadata(&b).unwrap().len();
        let selected = vec![dir.path().join("seg103.m4s"), dir.path().join("seg104.m4s")];
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg103.m4s", Path::new("init-b.mp4")),
                event("seg104.m4s", Path::new("init-b.mp4")),
            ]}),
        );
        let exact = load_plan_with_budget(&context, &path, &selected, size * 2).unwrap();
        assert_eq!(exact.len(), 2);
        assert!(exact.iter().all(|update| update.snapshot.is_ok()));
        let short = load_plan_with_budget(&context, &path, &selected, size * 2 - 1).unwrap();
        assert!(short[0].snapshot.is_ok());
        assert!(short[1]
            .snapshot
            .as_ref()
            .err()
            .unwrap()
            .to_string()
            .contains("raw-byte limit"));
        // The initial init has a separate allowance. The failed second snapshot is reported
        // at its boundary, before attempting to open the nonexistent seg104 media file.
        let report = super::super::validate_update_timeline(&context, &init, &selected, &short);
        assert_eq!(report.validation_state, "Invalid");
        assert_eq!(report.segments.len(), 1);
        assert_eq!(report.segments[0].state, ValidationState::Trusted);
        assert!(report.validation_results.failure.iter().any(|status| {
            status.code == "livevideo.manifest.invalid"
                && status
                    .explanation
                    .as_deref()
                    .unwrap()
                    .contains("raw-byte limit")
        }));

        let mut selected = selected;
        selected.push(dir.path().join("seg105.m4s"));
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg103.m4s", Path::new("init-b.mp4")),
                event("seg104.m4s", Path::new("init-b.mp4")),
                event("seg105.m4s", Path::new("not-read.mp4")),
            ]}),
        );
        let plan = load_plan_with_budget(&context, &path, &selected, size * 2 - 1).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(plan[1].snapshot.is_err());
    }

    #[test]
    fn verified_update_bytes_are_not_reread_at_installation() {
        let (dir, context, path) = signed_corpus(3600);
        let init = dir.path().join("init-a.mp4");
        let selected = super::super::collect_segments(&init, Path::new("seg*.m4s")).unwrap();
        let b = dir.path().join("init-b.mp4");
        let original = fs::read(&b).unwrap();
        let plan = load_plan(&context, &path, &selected).unwrap();
        assert_eq!(plan[0].snapshot.as_ref().unwrap().init_data, original);
        fs::remove_file(&b).unwrap();
        let report = super::super::validate_update_timeline(&context, &init, &selected, &plan);
        assert_eq!(report.validation_state, "Trusted");
        assert_eq!(report.segments.len(), 2);
        assert!(report.validation_results.failure.is_empty());
    }

    #[test]
    fn signed_a_to_b_timeline_requires_the_schedule_and_reports_trusted() {
        let (dir, context, path) = signed_corpus(3600);
        let init = dir.path().join("init-a.mp4");
        super::super::validate_live_video(&context, &init, Path::new("seg102.m4s"), None).unwrap();
        assert!(
            super::super::validate_live_video(&context, &init, Path::new("seg*.m4s"), None)
                .is_err()
        );
        let report = timeline(&dir, &context, &path);
        assert_eq!(report.validation_state, "Trusted");
        assert_eq!(report.segments.len(), 2);
        assert!(report.validation_results.failure.is_empty());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["segments"][1]["state"], "Trusted");
        assert_eq!(json["validation_results"]["failure"], json!([]));
        assert_eq!(json.as_object().unwrap().len(), 5);
        super::super::validate_live_video(&context, &init, Path::new("seg*.m4s"), Some(&path))
            .unwrap();
        // A boundary before the first selected media still uses the already-initialized validator.
        super::super::validate_live_video(&context, &init, Path::new("seg103.m4s"), Some(&path))
            .unwrap();
    }

    #[test]
    fn updates_preserve_sequence_continuity_and_replace_manifest_association() {
        let (dir, context, _) = signed_corpus(3600);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        install_context(
            &context,
            &dir.path().join("init-a.mp4"),
            &mut validator,
            &mut tracker,
            false,
        )
        .unwrap();
        validator
            .validate_verifiable_segment_info(
                &fs::read(dir.path().join("seg102.m4s")).unwrap(),
                &mut tracker,
            )
            .unwrap();
        install_context(
            &context,
            &dir.path().join("init-b.mp4"),
            &mut validator,
            &mut tracker,
            true,
        )
        .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
        // This is signed for B and within B's key bounds, but equals A's accepted sequence.
        // Its rejection is the baseline sequence rule, not a fork-only emsg-ID replay check.
        validator
            .validate_verifiable_segment_info(
                &fs::read(dir.path().join("equal102.m4s")).unwrap(),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 1);
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("strictly greater")));
        validator
            .validate_verifiable_segment_info(
                &fs::read(dir.path().join("old103.m4s")).unwrap(),
                &mut tracker,
            )
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("manifestId")));
        let failures = tracker.filter_errors().count();
        let b = fs::read(dir.path().join("seg103.m4s")).unwrap();
        validator
            .validate_verifiable_segment_info(&b, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), failures);
        validator
            .validate_verifiable_segment_info(&b, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), failures + 1);
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("strictly greater")));
    }

    #[test]
    fn rejected_signed_update_is_atomic_and_stops_before_target_media() {
        let (dir, context, path) = signed_corpus(0);
        let b = dir.path().join("init-b.mp4");
        assert!(read_context(&context, &b, &fs::read(&b).unwrap()).is_ok());
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        install_context(
            &context,
            &dir.path().join("init-a.mp4"),
            &mut validator,
            &mut tracker,
            false,
        )
        .unwrap();
        validator
            .validate_verifiable_segment_info(
                &fs::read(dir.path().join("seg102.m4s")).unwrap(),
                &mut tracker,
            )
            .unwrap();
        assert!(install_context(&context, &b, &mut validator, &mut tracker, true).is_err());
        let failures = tracker.filter_errors().count();
        assert!(failures > 0);
        validator
            .validate_verifiable_segment_info(
                &fs::read(dir.path().join("old103.m4s")).unwrap(),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), failures);
        fs::write(dir.path().join("seg103.m4s"), b"must not be read").unwrap();
        let report = timeline(&dir, &context, &path);
        assert_eq!(report.validation_state, "Invalid");
        assert_eq!(report.segments.len(), 1);
        assert!(report
            .validation_results
            .failure
            .iter()
            .any(|status| status.code == "livevideo.sessionkey.invalid"));
    }

    #[test]
    fn invalid_update_assets_have_invalid_json_reports_and_stop_at_boundary() {
        let (dir, context, path) = signed_corpus(3600);
        let b = dir.path().join("init-b.mp4");
        let original = fs::read(&b).unwrap();
        let mut tampered = original.clone();
        let mvhd = tampered
            .windows(4)
            .position(|window| window == b"mvhd")
            .unwrap();
        assert_eq!(tampered[mvhd + 4], 0);
        tampered[mvhd + 27] ^= 1;
        fs::write(dir.path().join("seg103.m4s"), b"must not be read").unwrap();
        for candidate in [
            Some(tampered),
            Some(INIT.to_vec()),
            Some(b"not BMFF".to_vec()),
            None,
        ] {
            if let Some(bytes) = candidate {
                fs::write(&b, bytes).unwrap();
            } else {
                fs::remove_file(&b).unwrap();
            }
            let report = timeline(&dir, &context, &path);
            assert_eq!(report.validation_state, "Invalid");
            assert_eq!(report.segments.len(), 1);
            let json = serde_json::to_value(&report).unwrap();
            assert_eq!(json["validation_state"], "Invalid");
            assert!(report
                .validation_results
                .failure
                .iter()
                .any(|status| status.code == "livevideo.manifest.invalid"));
            assert!(super::super::validate_live_video(
                &context,
                &dir.path().join("init-a.mp4"),
                Path::new("seg*.m4s"),
                Some(&path),
            )
            .is_err());
        }
    }

    #[test]
    fn initial_context_must_be_trusted_even_for_an_empty_schedule() {
        let (dir, context, _) = signed_corpus(3600);
        let path = schedule(&dir, json!({"version": 1, "updates": []}));
        let anchorless = Arc::new(
            C2paContext::new()
                .with_settings(
                    context
                        .settings()
                        .with_value("trust.anchors", json!([]))
                        .unwrap(),
                )
                .unwrap(),
        );
        let report = timeline(&dir, &anchorless, &path);
        assert_eq!(report.validation_state, "Invalid");
        assert!(report.segments.is_empty());
        assert!(!report.validation_results.failure.is_empty());
        for setting in ["verify.verify_after_reading", "verify.verify_trust"] {
            let disabled = C2paContext::new()
                .with_settings(context.settings().with_value(setting, false).unwrap())
                .unwrap();
            assert!(require_verification(&disabled).is_err());
        }
        fs::write(dir.path().join("init-a.mp4"), INIT).unwrap();
        assert_eq!(timeline(&dir, &context, &path).validation_state, "Invalid");
    }

    #[test]
    fn untrusted_update_does_not_reuse_the_initial_contexts_trust() {
        let (dir, context, path) = signed_corpus(3600);
        let only_leaf = |pem: &str| {
            json!([{
                "trust_kind": "manifest", "trust_uri": "https://example.test/local-fixture",
                "trust_anchors": "", "allowed_list": pem,
                "trust_config": include_str!("../sample/store.cfg"),
            }])
        };
        let receiver = Arc::new(
            C2paContext::new()
                .with_settings(
                    context
                        .settings()
                        .with_value(
                            "trust.anchors",
                            only_leaf(include_str!("../sample/es256_certs.pem")),
                        )
                        .unwrap(),
                )
                .unwrap(),
        );
        let other_signer = c2pa::create_signer::from_keys(
            include_bytes!("../sample/ps256.pub"),
            include_bytes!("../sample/ps256.pem"),
            SigningAlg::Ps256,
            None,
        )
        .unwrap();
        let signing = C2paContext::new()
            .with_settings(
                context
                    .settings()
                    .with_value(
                        "trust.anchors",
                        only_leaf(include_str!("../sample/ps256.pub")),
                    )
                    .unwrap(),
            )
            .unwrap()
            .with_signer(other_signer);
        let _settings = ProducerSettings::new(signing.settings());
        let mut b = producer(&signing, 103, 3600);
        let signed = b
            .sign_init_segment(INIT, "video/mp4", signing.signer().unwrap())
            .unwrap();
        fs::write(dir.path().join("init-b.mp4"), signed).unwrap();
        let report = timeline(&dir, &receiver, &path);
        assert_eq!(report.validation_state, "Invalid");
        assert_eq!(report.segments.len(), 1);
        assert!(report.validation_results.failure.iter().any(|status| {
            status.code == "livevideo.manifest.invalid"
                && status.explanation.as_deref().unwrap().contains("Trusted")
        }));
    }

    #[test]
    fn trusted_manifest_box_init_is_not_admitted_to_update_profile() {
        let context = trusted_context();
        let mut builder = c2pa::Builder::from_shared_context(&context)
            .with_definition(MANIFEST)
            .unwrap();
        let mut signed = Cursor::new(Vec::new());
        builder
            .sign(
                context.signer().unwrap(),
                "video/mp4",
                &mut Cursor::new(INIT),
                &mut signed,
            )
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let init = dir.path().join("init-a.mp4");
        fs::write(&init, signed.into_inner()).unwrap();
        let path = schedule(&dir, json!({"version": 1, "updates": []}));
        let report = timeline(&dir, &context, &path);
        assert_eq!(report.validation_state, "Invalid");
        assert!(report.validation_results.failure.iter().any(|status| {
            status
                .explanation
                .as_deref()
                .unwrap()
                .contains("not manifest-box streams")
        }));
    }

    #[test]
    fn reader_verified_v1_vendor_labels_are_not_restricted_to_urn_c2pa() {
        let context = trusted_context();
        let _settings = ProducerSettings::new(context.settings());
        let mut definition: Value = serde_json::from_str(MANIFEST).unwrap();
        definition["claim_version"] = json!(1);
        definition["vendor"] = json!("example");
        let mut signer = LiveVideoVsiSigner::from_signing_key(
            definition.to_string(),
            context.signer().unwrap(),
            Ed25519SessionKey::from_bytes(&[0x42; 32]),
            b"v1-key".to_vec(),
            102,
            3600,
        )
        .unwrap();
        let signed = signer
            .sign_init_segment(INIT, "video/mp4", context.signer().unwrap())
            .unwrap();
        let verified = read_context(&context, Path::new("init.mp4"), &signed).unwrap();
        assert!(!verified.manifest_id.is_empty());
        assert!(!verified.manifest_id.starts_with("urn:c2pa:"));
    }
}

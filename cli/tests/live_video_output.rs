// Copyright 2026 Adobe. All rights reserved.
// This file is licensed under the Apache-2.0 or MIT license, at your option.

#![cfg(all(feature = "unstable_live_video", not(target_os = "wasi")))]

use std::{fs, path::Path, process::Command};

use assert_cmd::cargo;
use serde_json::json;

#[test]
fn legacy_unsigned_init_keeps_json_stdout_and_human_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let init = dir.path().join("init.mp4");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sdk/tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4"),
        &init,
    )
    .unwrap();
    let settings = dir.path().join("settings.json");
    fs::write(
        &settings,
        r#"{"verify":{"ocsp_fetch":false,"remote_manifest_fetch":false}}"#,
    )
    .unwrap();
    let output = Command::new(cargo::cargo_bin!("c2patool"))
        .arg(&init)
        .arg("--settings")
        .arg(settings)
        .args(["live-video", "--segments_glob", "absent-*.m4s"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        json!({
            "validation_state": "Valid",
            "method": "19.3 (per-segment C2PA Manifest Box)",
            "init_segment": init.display().to_string(),
            "segments": [],
            "validation_results": {"failure": []},
        })
    );
    let progress = String::from_utf8(output.stderr).unwrap();
    assert!(progress.contains("Method:    19.3 (per-segment C2PA Manifest Box)"));
    assert!(progress.contains("No segments found matching:"));
}

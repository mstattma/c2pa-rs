// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

// Tests assert by panicking; the crate-wide deny is meant for library code.
#![allow(clippy::unwrap_used)]

//! Multi-rendition (ABR ladder) signing of single-file fragmented BMFF assets.
//!
//! One claim covers the whole ladder: the single `c2pa.hash.bmff.v3` assertion
//! carries one `MerkleMap` per rendition and every rendition ships the same
//! manifest, so the thing under test is that each rendition is bound to, and
//! validated against, its own map.

use std::{io::Cursor, path::PathBuf};

use serde_bytes::ByteBuf;

use super::{BmffHash, MerkleMap, SINGLE_RENDITION_ID};
use crate::{
    asset_handlers::bmff_io::read_bmff_c2pa_boxes,
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    utils::test_signer::test_signer,
    validation_status::ASSERTION_BMFFHASH_MATCH,
    Builder, Context, Reader, Result, Settings, Signer, SigningAlg, ValidationState,
};

const RELATIVE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments.mp4");
const ABSOLUTE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments_absolute.mp4");
const FLAT: &[u8] = include_bytes!("../../tests/fixtures/video1_no_manifest.mp4");
const DEFINITION: &str = r#"{"title":"ladder","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;

fn builder() -> Builder {
    Builder::default().with_definition(DEFINITION).unwrap()
}

// Deliberately independent of the SDK's BMFF tree helpers.
#[derive(Clone, Copy, Debug)]
struct B {
    start: usize,
    payload: usize,
    end: usize,
    kind: [u8; 4],
}

fn roots(data: &[u8]) -> Vec<B> {
    let mut result = Vec::new();
    let mut at = 0;
    while data.len() - at >= 8 {
        let size = u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
        let (size, header) = match size {
            0 => (data.len() - at, 8),
            1 => (
                u64::from_be_bytes(data[at + 8..at + 16].try_into().unwrap()) as usize,
                16,
            ),
            _ => (size as usize, 8),
        };
        assert!(size >= header && at + size <= data.len());
        result.push(B {
            start: at,
            payload: at + header,
            end: at + size,
            kind: data[at + 4..at + 8].try_into().unwrap(),
        });
        at += size;
    }
    result
}

/// Byte range of the embedded manifest box, which is the only part of two
/// otherwise equivalent signings that may differ.
fn manifest_box(data: &[u8]) -> std::ops::Range<usize> {
    let b = roots(data)
        .into_iter()
        .find(|b| {
            b.kind == *b"uuid"
                && matches!(
                    data.get(b.payload + 20..b.payload + 29),
                    Some(b"manifest\0" | b"original\0")
                )
        })
        .unwrap();
    b.start..b.end
}

/// The manifest box's auxiliary locator must point at this rendition's first
/// `merkle` box. It is rewritten when the signed manifest is patched in, so a
/// stale value would only show up here.
fn check_aux_locator(signed: &[u8]) {
    let root = roots(signed);
    let first_merkle = root
        .iter()
        .find(|b| {
            b.kind == *b"uuid" && signed.get(b.payload + 20..b.payload + 27) == Some(b"merkle\0")
        })
        .unwrap();
    let primary = signed;
    let at = manifest_box(primary).start;
    let payload = root.iter().find(|b| b.start == at).unwrap().payload;
    assert_eq!(
        u64::from_be_bytes(signed[payload + 29..payload + 37].try_into().unwrap()),
        first_merkle.start as u64
    );
}

/// A different encode of the same content: same box layout, same track, other
/// media bytes, so each rendition must get leaf hashes of its own.
fn rendition(base: &[u8], seed: u8) -> Vec<u8> {
    let mut data = base.to_vec();
    for b in roots(base).iter().filter(|b| b.kind == *b"mdat") {
        data[b.end - 1] ^= seed;
    }
    data
}

fn ladder() -> Vec<Vec<u8>> {
    vec![
        rendition(RELATIVE, 1),
        rendition(RELATIVE, 2),
        rendition(ABSOLUTE, 3),
        rendition(ABSOLUTE, 4),
    ]
}

fn binding(data: &[u8]) -> BmffHash {
    let mut stream = Cursor::new(data);
    let reader = Reader::default()
        .with_stream("video/mp4", &mut stream)
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    assert!(
        reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .is_some_and(|s| s
                .success()
                .iter()
                .any(|s| s.code() == ASSERTION_BMFFHASH_MATCH)),
        "{reader}"
    );
    let mut hash: BmffHash = reader
        .active_manifest()
        .unwrap()
        .find_assertion("c2pa.hash.bmff.v3")
        .unwrap();
    hash.set_bmff_version(3); // Deserializing assertion data alone does not carry its label version.
    hash
}

fn maps(hash: &BmffHash) -> &Vec<MerkleMap> {
    hash.merkle.as_ref().unwrap()
}

struct Signed {
    dir: tempfile::TempDir,
    sources: Vec<PathBuf>,
    outputs: Vec<PathBuf>,
    manifest: Vec<u8>,
}

fn sign_ladder(renditions: &[Vec<u8>]) -> Signed {
    let dir = tempfile::tempdir().unwrap();
    let mut sources = Vec::new();
    let mut outputs = Vec::new();
    for (i, data) in renditions.iter().enumerate() {
        let source = dir.path().join(format!("rendition{i}.mp4"));
        std::fs::write(&source, data).unwrap();
        sources.push(source);
        outputs.push(dir.path().join(format!("signed{i}.mp4")));
    }
    let manifest = builder()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
        .unwrap();
    Signed {
        dir,
        sources,
        outputs,
        manifest,
    }
}

#[test]
fn ladder_binds_every_rendition_to_its_own_map() {
    let renditions = ladder();
    let signed = sign_ladder(&renditions);
    let count = renditions.len();

    for (index, output) in signed.outputs.iter().enumerate() {
        // uniqueId is 1-based per the specification.
        let unique_id = index + 1;
        let data = std::fs::read(output).unwrap();
        let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&data)).unwrap();

        // The identical manifest is embedded in every rendition.
        assert_eq!(
            boxes.manifest_bytes.as_deref(),
            Some(signed.manifest.as_slice())
        );

        // Every fragment of this rendition names this rendition's tree, and a
        // real ladder renumbers every track to 1, so uniqueId is all there is.
        assert_eq!(boxes.bmff_merkle.len(), 3);
        for merkle in &boxes.bmff_merkle {
            assert_eq!(merkle.unique_id, unique_id);
            assert_eq!(merkle.local_id, 1);
        }

        check_aux_locator(&data);

        // One claim, one assertion, one map per rendition.
        let hash = binding(&data);
        assert!(hash.hash().is_none());
        assert_eq!(maps(&hash).len(), count);
        for (i, map) in maps(&hash).iter().enumerate() {
            assert_eq!(map.unique_id, i + 1);
            assert_eq!(map.local_id, 1);
            assert_eq!(map.count, 3);
            assert_eq!(map.hashes.0.len(), 3);
            assert!(map.init_hash.is_some());
        }
        hash.verify_stream_hash(&mut Cursor::new(&data), None)
            .unwrap();

        // The map that was checked is this rendition's own: breaking a sibling's
        // leaf row leaves this rendition valid, breaking its own does not.
        let mut broken = binding(&data);
        broken.merkle.as_mut().unwrap()[index].hashes.0[0] = ByteBuf::from(vec![0u8; 32]);
        assert!(broken
            .verify_stream_hash(&mut Cursor::new(&data), None)
            .is_err());

        let sibling = (index + 1) % count;
        let mut untouched = binding(&data);
        untouched.merkle.as_mut().unwrap()[sibling].hashes.0[0] = ByteBuf::from(vec![0u8; 32]);
        untouched.merkle.as_mut().unwrap()[sibling].init_hash = Some(ByteBuf::from(vec![0u8; 32]));
        untouched
            .verify_stream_hash(&mut Cursor::new(&data), None)
            .unwrap();
    }

    // No two renditions share a leaf row, and renditions whose initialization
    // differs get different initHashes. (Two encodes that happen to share a
    // moov legitimately share an initHash, so that is not a pairwise check.)
    let hash = binding(&std::fs::read(&signed.outputs[0]).unwrap());
    for i in 0..count {
        for j in 0..i {
            assert_ne!(maps(&hash)[i].hashes.0, maps(&hash)[j].hashes.0);
        }
    }
    assert_ne!(maps(&hash)[0].init_hash, maps(&hash)[2].init_hash);

    // Every source is untouched; signing writes only to the outputs.
    for (source, original) in signed.sources.iter().zip(&renditions) {
        assert_eq!(&std::fs::read(source).unwrap(), original);
    }
    drop(signed.dir);
}

/// `verify_after_sign` re-reads every rendition through the full store
/// validation, which is where a mis-selected map would show up as an error
/// rather than as a silently wrong hash.
#[test]
fn ladder_verifies_after_signing_when_asked() {
    let renditions = ladder();
    let dir = tempfile::tempdir().unwrap();
    let mut sources = Vec::new();
    let mut outputs = Vec::new();
    for (i, data) in renditions.iter().enumerate() {
        let source = dir.path().join(format!("rendition{i}.mp4"));
        std::fs::write(&source, data).unwrap();
        sources.push(source);
        outputs.push(dir.path().join(format!("signed{i}.mp4")));
    }
    let settings = Settings::new()
        .with_value("verify.verify_after_sign", true)
        .unwrap();
    Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
        .unwrap();
    for output in &outputs {
        binding(&std::fs::read(output).unwrap());
    }
}

#[test]
fn ladder_of_one_matches_signing_that_rendition_alone() {
    for input in [RELATIVE, ABSOLUTE] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.mp4");
        std::fs::write(&source, input).unwrap();

        let alone = dir.path().join("alone.mp4");
        builder()
            .sign_file(test_signer(SigningAlg::Es256).as_ref(), &source, &alone)
            .unwrap();

        let rung = dir.path().join("rung.mp4");
        builder()
            .sign_ladder_files(
                test_signer(SigningAlg::Es256).as_ref(),
                std::slice::from_ref(&source),
                std::slice::from_ref(&rung),
            )
            .unwrap();

        let alone = std::fs::read(alone).unwrap();
        let rung = std::fs::read(rung).unwrap();

        // The two manifests are the same length but not the same bytes: each
        // signing mints a fresh instance id and claim label, and the signature
        // covers them. Everything outside the manifest box, which is what the
        // binding actually covers, has to be identical.
        let box_alone = manifest_box(&alone);
        let box_rung = manifest_box(&rung);
        assert_eq!(box_alone, box_rung);
        assert_eq!(alone.len(), rung.len());
        assert_eq!(alone[..box_alone.start], rung[..box_rung.start]);
        assert_eq!(alone[box_alone.end..], rung[box_rung.end..]);

        // ...and so is the binding itself, down to the rendition id.
        let alone = binding(&alone);
        let rung = binding(&rung);
        assert_eq!(maps(&alone), maps(&rung));
        assert_eq!(maps(&rung).len(), 1);
        assert_eq!(maps(&rung)[0].unique_id, SINGLE_RENDITION_ID);
    }
}

#[test]
fn ladder_rejects_mixed_and_overlapping_input() {
    let dir = tempfile::tempdir().unwrap();
    let fragmented = dir.path().join("fragmented.mp4");
    std::fs::write(&fragmented, RELATIVE).unwrap();
    let flat = dir.path().join("flat.mp4");
    std::fs::write(&flat, FLAT).unwrap();
    let out_a = dir.path().join("a.mp4");
    let out_b = dir.path().join("b.mp4");

    let fail = |sources: &[PathBuf], outputs: &[PathBuf]| -> String {
        builder()
            .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), sources, outputs)
            .unwrap_err()
            .to_string()
    };

    // A rendition that is not single-file fragmented cannot join the ladder.
    let error = fail(
        &[fragmented.clone(), flat.clone()],
        &[out_a.clone(), out_b.clone()],
    );
    assert!(
        // Renditions are numbered from 1, so the flat one is rendition 2.
        error.contains("rendition 2 is not a single-file fragmented BMFF"),
        "{error}"
    );

    // Multiplexed assets stay rejected where they always were.
    let mut multiplexed = RELATIVE.to_vec();
    let root = roots(&multiplexed);
    let moov = *root.iter().find(|b| b.kind == *b"moov").unwrap();
    let inner = {
        let mut at = moov.payload;
        let mut found = None;
        while at < moov.end {
            let size = u32::from_be_bytes(multiplexed[at..at + 4].try_into().unwrap()) as usize;
            if &multiplexed[at + 4..at + 8] == b"trak" {
                found = Some((at, at + size));
            }
            at += size;
        }
        found.unwrap()
    };
    let mut extra = multiplexed[inner.0..inner.1].to_vec();
    extra[20..24].copy_from_slice(&2u32.to_be_bytes()); // tkhd track id
    multiplexed.splice(moov.end..moov.end, extra.iter().copied());
    let grown = (moov.end - moov.start + extra.len()) as u32;
    multiplexed[moov.start..moov.start + 4].copy_from_slice(&grown.to_be_bytes());
    let multiplexed_path = dir.path().join("multiplexed.mp4");
    std::fs::write(&multiplexed_path, &multiplexed).unwrap();
    let error = fail(&[multiplexed_path], std::slice::from_ref(&out_a));
    assert!(error.contains("multiplexed/changing tracks"), "{error}");

    // An output may not be an input, or another rendition's output.
    let error = fail(
        std::slice::from_ref(&fragmented),
        std::slice::from_ref(&fragmented),
    );
    assert!(
        error.contains("must not be any rendition's input"),
        "{error}"
    );
    let error = fail(
        &[fragmented.clone(), fragmented.clone()],
        &[out_a.clone(), out_a.clone()],
    );
    assert!(error.contains("its own output path"), "{error}");
    let error = fail(
        std::slice::from_ref(&fragmented),
        &[out_a.clone(), out_b.clone()],
    );
    assert!(error.contains("exactly one output path"), "{error}");
    let error = fail(&[], &[]);
    assert!(
        error.contains("at least one rendition path must be provided"),
        "{error}"
    );

    // The manifest has to be embedded in every rendition, so a detached one is
    // refused rather than silently bound to bytes that will not carry it.
    for remote in [false, true] {
        let mut detached = builder();
        detached.set_no_embed(true);
        if remote {
            detached.set_remote_url("https://example.invalid/detached.c2pa");
        }
        let error = detached
            .sign_ladder_files(
                test_signer(SigningAlg::Es256).as_ref(),
                std::slice::from_ref(&fragmented),
                std::slice::from_ref(&out_a),
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("remote and sidecar manifests are not supported"),
            "{error}"
        );
    }

    // Re-signing an already bound rendition is still refused.
    let signed = sign_ladder(&[RELATIVE.to_vec()]);
    let error = fail(&[signed.outputs[0].clone()], std::slice::from_ref(&out_b));
    assert!(error.contains("existing Merkle boxes"), "{error}");
}

#[test]
fn ladder_rejects_overlap_by_file_identity_not_by_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    let source_a = dir.path().join("a.mp4");
    std::fs::write(&source_a, rendition(RELATIVE, 1)).unwrap();
    let source_b = dir.path().join("b.mp4");
    std::fs::write(&source_b, rendition(RELATIVE, 2)).unwrap();
    let sources = [source_a.clone(), source_b.clone()];
    let untouched = |path: &PathBuf, seed: u8| {
        assert_eq!(std::fs::read(path).unwrap(), rendition(RELATIVE, seed));
    };

    let fail = |sources: &[PathBuf], outputs: &[PathBuf]| -> String {
        builder()
            .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), sources, outputs)
            .unwrap_err()
            .to_string()
    };

    // `subdir/../a.mp4` is a different string but the same file as `a.mp4`:
    // a spelling check lets the writer read a rendition while truncating it.
    let alias_of_a = subdir.join("..").join("a.mp4");
    let error = fail(&sources, &[alias_of_a, dir.path().join("out_b.mp4")]);
    assert!(
        error.contains("must not be any rendition's input"),
        "{error}"
    );
    untouched(&source_a, 1);

    // The other rendition's input, aliased, is just as much an input.
    let alias_of_b = subdir.join("..").join("b.mp4");
    let error = fail(&sources, &[alias_of_b, dir.path().join("out_b.mp4")]);
    assert!(
        error.contains("must not be any rendition's input"),
        "{error}"
    );
    untouched(&source_b, 2);

    // A hard link is a second name for the source's inode, and no amount of
    // path comparison sees through it.
    let link_of_a = dir.path().join("link_of_a.mp4");
    std::fs::hard_link(&source_a, &link_of_a).unwrap();
    let error = fail(&sources, &[link_of_a, dir.path().join("out_b.mp4")]);
    assert!(
        error.contains("same file as a rendition's input"),
        "{error}"
    );
    untouched(&source_a, 1);

    // Two spellings of one output would collapse the ladder into one file.
    let out = dir.path().join("out.mp4");
    let error = fail(&sources, &[out.clone(), subdir.join("..").join("out.mp4")]);
    assert!(
        error.contains("every rendition needs its own output path"),
        "{error}"
    );

    // ...as would two outputs that are hard links of one another.
    let out_x = dir.path().join("x.mp4");
    std::fs::write(&out_x, b"").unwrap();
    let out_y = dir.path().join("y.mp4");
    std::fs::hard_link(&out_x, &out_y).unwrap();
    let error = fail(&sources, &[out_x, out_y]);
    assert!(error.contains("hard links of one another"), "{error}");

    // A dangling symlink named like an output would send the write to its
    // target -- here the other rendition's output, collapsing the ladder.
    #[cfg(unix)]
    {
        let out_y = dir.path().join("dangling_target.mp4");
        let out_x = dir.path().join("dangling.mp4");
        std::os::unix::fs::symlink(&out_y, &out_x).unwrap();
        let error = fail(&sources, &[out_x, out_y]);
        assert!(
            error.contains("symlink to a file that does not exist"),
            "{error}"
        );
    }

    // The checks resolve, they do not forbid, relative spellings: an output
    // that only does not exist yet is fine when named through `..`.
    let fresh = subdir.join("..").join("fresh_a.mp4");
    builder()
        .sign_ladder_files(
            test_signer(SigningAlg::Es256).as_ref(),
            &sources,
            &[fresh, dir.path().join("fresh_b.mp4")],
        )
        .unwrap();
    assert_eq!(
        maps(&binding(
            &std::fs::read(dir.path().join("fresh_a.mp4")).unwrap()
        ))
        .len(),
        2
    );
    untouched(&source_a, 1);
    untouched(&source_b, 2);
}

struct DynamicSigner(Box<dyn Signer>);
struct Dynamic;
impl DynamicAssertion for Dynamic {
    fn label(&self) -> String {
        "com.castlabs.ladder-test".into()
    }
    fn reserve_size(&self) -> Result<usize> {
        Ok(64)
    }
    fn content(
        &self,
        _: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent> {
        assert_eq!(size, Some(64));
        let binding = claim
            .assertions()
            .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
            .unwrap();
        let mut content = vec![0xa2, 0x64, b'h', b'a', b's', b'h', 0x58, 0x20];
        content.extend(binding.hash());
        content.extend([0x63, b'p', b'a', b'd', 0x73]);
        content.extend([b'x'; 19]);
        Ok(DynamicAssertionContent::Cbor(content))
    }
}
impl Signer for DynamicSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data)
    }
    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }
    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.certs()
    }
    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }
    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        vec![Box::new(Dynamic)]
    }
}

/// A dynamic assertion is written after every rendition's hashes are in the
/// claim, so it endorses the finished ladder binding rather than a placeholder.
#[test]
fn ladder_dynamic_assertion_endorses_the_finished_binding() {
    let renditions = ladder();
    let dir = tempfile::tempdir().unwrap();
    let mut sources = Vec::new();
    let mut outputs = Vec::new();
    for (i, data) in renditions.iter().enumerate() {
        let source = dir.path().join(format!("rendition{i}.mp4"));
        std::fs::write(&source, data).unwrap();
        sources.push(source);
        outputs.push(dir.path().join(format!("signed{i}.mp4")));
    }
    let signer = DynamicSigner(test_signer(SigningAlg::Es256));
    builder()
        .sign_ladder_files(&signer, &sources, &outputs)
        .unwrap();

    #[derive(serde::Deserialize)]
    struct Endorsement {
        hash: serde_bytes::ByteBuf,
    }

    for output in &outputs {
        let data = std::fs::read(output).unwrap();
        let mut stream = Cursor::new(&data);
        let reader = Reader::default()
            .with_stream("video/mp4", &mut stream)
            .unwrap();
        assert_ne!(
            reader.validation_state(),
            ValidationState::Invalid,
            "{reader}"
        );
        let endorsement: Endorsement = reader
            .active_manifest()
            .unwrap()
            .find_assertion("com.castlabs.ladder-test")
            .unwrap();
        let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&data)).unwrap();
        let store = crate::store::Store::from_jumbf(
            &boxes.manifest_bytes.unwrap(),
            &mut crate::status_tracker::StatusTracker::default(),
        )
        .unwrap();
        let final_binding = store
            .provenance_claim()
            .unwrap()
            .assertions()
            .iter()
            .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
            .unwrap();
        assert_eq!(endorsement.hash.as_ref(), final_binding.hash());
    }
}

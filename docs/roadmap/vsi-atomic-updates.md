# VSI Atomic Context Updates: SDK Draft

Status: local upstream-staging implementation draft based on `75ec57b5`
(the clean #2631 baseline), on `feat/vsi-atomic-context-updates`. This is
an SDK API proposal, not an adopted specification change or a statement
that the Castlabs fork's broader live-video behavior has been upstreamed.
No CLI changes are included.

## Proposed API

Behind the existing `unstable_live_video` feature:

```rust,ignore
pub fn update_vsi_context(
    &mut self,
    init_segment: Option<&[u8]>,
    assertion: &SessionKeys,
    manifest_id: &str,
    ee_cert_der: Option<&[u8]>,
    tracker: &mut StatusTracker,
) -> Result<()>;
```

This method updates an existing VSI validator. It is not an initialization
or restart API. Existing `validate_init_segment` and
`validate_session_keys` setup behavior is unchanged, including the legacy
aggregate-mode result semantics and the possibility of retaining only
the verified subset of a session-key assertion.

## Caller Prerequisites

Before invoking the update, the caller must use `Reader` to verify the
candidate manifest's signature, trust, assertion integrity and applicable
initialization-segment hard binding. Extract the `SessionKeys`, active
manifest label and end-entity certificate from that same verified Reader
manifest, not from a configured producer or from unrelated manifests.
The draft tests require `ValidationState::Trusted` and no active-manifest
failures before extracting this material.

The raw arguments are not proof that those Reader checks occurred. The
optional init check below does not replace Reader validation. A caller
must not install material from an untrusted or hard-binding-invalid init.
The caller also owns logical-stream scope and update ordering; this API
does not authenticate that an update belongs to the same logical stream,
authorize a publisher transition, or prove update freshness.

The validator must already have both a stored expected manifest ID and
nonempty session keys. No accepted media segment is required. Because the
baseline has no stored init layout, this prerequisite cannot attest that
an init was previously validated. A private flag rejects this update API
once the validator has accepted a per-segment Manifest Box; the flag does
not add method-switching restrictions to the legacy validation/setup APIs.
Failed Manifest Box validation does not set the flag.

## Installation Contract

1. Validate a detached candidate without modifying the installed validator.
2. For `Some(init)`, run the existing `validate_init_segment` check: reject
   a top-level `mdat`. `None` skips this check. The baseline method takes
   `&self`, stores no init data and does not establish a valid track layout.
3. Require a nonempty candidate manifest ID and nonempty, unique key IDs
   as resolved by the existing `kid_from_cose_key` helper. This guards
   against empty/unresolvable IDs and ambiguous key selection only in the
   new update API; it does not tighten legacy setup policy. Distinct CBOR
   representations resolving to the same ID are duplicates.
4. Run the existing `validate_session_keys` checks on the candidate:
   nonempty key list, supplied EE certificate, resolvable key IDs,
   nonzero validity periods and verification of every key's `signerBinding`
   against the supplied EE certificate using the existing crypto backend.
5. Reject on an error, any newly logged failure, or an incomplete/empty
   candidate key set. Never install a verified subset as a successful update.
6. Commit only the complete candidate session keys and expected manifest ID.
   Preserve the entire `previous_segment` and the method flag unchanged.

`Ok(())` means the complete candidate was installed and every key passed
these existing installation checks. This is true with either
`ContinueWhenPossible` or `StopOnFirstError`. An `Err` means no validator
state was changed; diagnostics already written to the supplied tracker
remain available. The new-failure count is relative to this invocation:
earlier tracker failures neither disappear nor veto an independently good
update. Aggregating trackers may collect several failures, while
stop-on-first trackers may return before checking the rest of a candidate.

Installation does not mean that every key is applicable to the next media
segment. The existing media path still checks key sequence bounds,
`createdAt`/validity-window applicability, VSI signature, manifest ID,
sequence continuity and BMFF hash. This draft does not strengthen those
checks or change the existing VSI failure codes (including the separate
sequence-failure-code workstream).

This is replacement, not a history or merge mechanism. After success,
media referring to an old manifest/key context is not accepted via a
retained old context. After failure, the old context remains available
and its next otherwise-valid media segment can still be validated.

## Differences From The Fork

The upstream baseline stores only `previous_segment`, session keys and
the expected manifest ID; this draft adds only the private Manifest Box
flag. It has no parsed track/timescale/default-duration state, seen-EMSG-ID
set, coverage model, gap reporting or playback-interval suppression state.
There is no state of those kinds to preserve here.

The guarantee is preservation of the existing accepted-segment sequence
baseline, not parity with the fork's replay/coverage protections. Existing
strictly increasing sequence validation remains effective across an
update, but this is not an added replay-ID guarantee. The optional init
does not compare track IDs, timescales, sample durations, codecs or sample
entries. No fork one-moof/track parser, trusted-context ABI, public CBOR
surface, alternate crypto implementation, vendor validation codes, recovery
path, signed restart, new algorithm names or trust-root migration is
included. No multi-manifest history or multi-track policy is introduced.

## Draft Test Coverage And Verification Status

`sdk/src/live_video/verified_updates_tests.rs` adds cases intended to cover:

- A real Reader-trusted A-to-B init/manifest update on the same producer
  with the existing bunny init and consecutive media fixtures; assertion,
  label and leaf certificate are extracted from Reader output.
- Preservation of the old accepted-segment baseline and rejection of an
  equal sequence after the update, using the unchanged baseline failure code.
- Invalid bindings, valid/invalid multi-key orders, zero validity period,
  empty key list, missing/wrong certificate, empty manifest ID,
  missing/empty/duplicate key IDs and init containing `mdat`; rejected
  candidates leave the old context and its next media usable.
- Complete two-key installation without init bytes, and successful updates
  despite earlier tracker failures. The two-key raw-API case combines keys
  extracted from separately verified manifests sharing the same leaf; it
  is deliberately not a Reader trust claim for that synthetic assertion.
- Initialized-context and Manifest Box guards, plus caller-side rejection
  of an anchorless Reader and of init hard-binding tampering.

Both tracker error behaviors are represented. The receiver helper borrows
the requested error behavior and constructs a fresh variant for each tracker.
Missing/empty key-ID fixtures remove every label that resolves to integer 2
under the production coercion rule, including Reader's JSON-shaped text
labels, and assert the resulting resolved ID.

The test signer has no TSA; manifest, hash and trust verification remain
enabled. The anchorless Reader explicitly sets `trust.anchors` to an empty
list rather than using `Trust::default()`, which loads fixture roots under
`cfg(test)`. Automatic timestamp generation, OCSP fetch, remote manifest
fetch and certificate-status fetch are disabled; the test Context also
blocks all network hosts. The baseline producer uses thread-local settings
internally, so a test-only guard copies the core/trust/verify/builder settings
from the test Context for producer operations. It restores those sections
afterward and asserts equality with the entire saved typed Settings snapshot,
including the prior network and trust configuration. No production producer
API is changed.

The real-Reader cases depend on a separate prerequisite in
`sdk/src/live_video/session_key_validation.rs`: the Reader JSON round trip
loses the outer CBOR tag on `signerBinding`, while the baseline extractor
accepts only tag 18. That prerequisite is isolated in
[mstattma/c2pa-rs#38](https://github.com/mstattma/c2pa-rs/pull/38), branch
`fix/vsi-reader-signer-binding`. The API draft is stacked on that fix and keeps
the real Reader-extracted material unchanged; it neither modifies the
extractor nor works around it in the test material helper. Until that
prerequisite is merged, these cases are not expected to pass on the clean
baseline.

No Cargo commands, builds or test executions have been performed for this
draft. Compilation, test execution and crypto-backend verification remain
pending the operator's serialized build window. Required inputs are the
existing SDK fixtures/test trust configuration, `unstable_live_video`, and
a supported crypto backend. Tests must not be treated as passing evidence
until that verification is explicitly run.

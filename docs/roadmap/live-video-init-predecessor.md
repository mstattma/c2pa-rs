# Per-Segment Manifest Continuity: Bootstrap And Unavailable Predecessors

Discussion and implementation-tracking proposal only. This is not an approved
specification interpretation or a request to change VSI. The baseline is
[contentauth/c2pa-rs#2631](https://github.com/contentauth/c2pa-rs/pull/2631) at
`75ec57b5f1f2c3c06440a0f68bfa6cc9bda71b03`.
That is the #2631 branch-head snapshot, including the CBOR-native session-key
changes merged via #2638; the commit subject's #2638 is not this proposal's base PR.

Tracked in [mstattma/c2pa-rs#21](https://github.com/mstattma/c2pa-rs/issues/21).

## Specification Boundary

The published C2PA 2.4 text and current specs-core source distinguish two rules
for the per-segment C2PA Manifest Box method:

- With `continuityMethod = "c2pa.manifestId"`, `previousManifestId` shall be
  present. Absence is `livevideo.continuityMethod.invalid`.
- The value shall match the preceding segment's manifest ID. A mismatch is
  `livevideo.segment.invalid`.

The first-segment exception is written for sequence comparison, not for these
predecessor rules. However, the initialization clause is conditional on use
cases that "require (or desire)" an initialization segment. It does not explicitly
define the init manifest as the first media segment's predecessor, a genesis
value without init, or the result when the receiver lacks the predecessor.

Sources:

- [2.4 initialization clause](https://github.com/c2pa-org/specs-core/blob/712d8baf6c7c482d754dce5919f7f4f4b443d7e6/docs/modules/specs/partials/Live-Video/live-video.adoc#L44-L48)
- [2.4 per-segment validation](https://github.com/c2pa-org/specs-core/blob/712d8baf6c7c482d754dce5919f7f4f4b443d7e6/docs/modules/specs/partials/Live-Video/live-video.adoc#L224-L231)
- [Current source, assertion definition](https://github.com/c2pa-org/specs-core/blob/24b870e4d86719f56f47f7627f1ff51f785c6141/docs/modules/specs/partials/Live-Media/live-media.adoc#L73-L83)
- [Current source, validation](https://github.com/c2pa-org/specs-core/blob/24b870e4d86719f56f47f7627f1ff51f785c6141/docs/modules/specs/partials/Live-Media/live-media.adoc#L331-L338)
- [Method-specific CDDL](https://github.com/c2pa-org/specs-core/blob/24b870e4d86719f56f47f7627f1ff51f785c6141/docs/modules/specs/partials/schemas/cddl/livevideo-segment.cddl#L5-L20)

## Existing Implementations Disagree

At the #2631 baseline:

- `LiveVideoSigner::sign_init_segment` is optional and does not update the
  predecessor state. The first media assertion therefore omits
  `previousManifestId`, including after an init was signed. Tests explicitly
  preserve this behavior.
- `validate_manifest_id_continuity` returns success when no preceding media
  state exists, before checking required field presence.

The Castlabs fork already uses a different bootstrap policy, introduced in
[d33d869a](https://github.com/castlabs/c2pa-rs/commit/d33d869a08a57f2de6941245d726af6ec648b7c8):

- Signing init establishes its manifest ID as the predecessor of first media.
- Media signing requires a signed init or an explicitly resumed predecessor.
- A receiver can register the verified init manifest and compare the first
  media assertion against it.

These are implementation choices to discuss, not proof that the spec requires
every stream to have init or every first received segment to reference init.
An unconditional missing-field fix is held until bootstrap semantics are clear;
changing only the validator would reject the baseline signer's own first output.

## Questions To Resolve

1. **Generator bootstrap.** When init is present, should the first media
   `previousManifestId` refer to its manifest? What is the conforming genesis
   value when there is no separate init? Does init need a live-segment assertion?
2. **Unavailable predecessor.** Does "previous segment" mean the immediate
   produced predecessor or the last segment received/validated? On a late join
   or loss, should continuity fail, be deferred, or be reported as unverified
   while independently authenticating the current segment?
3. **Reinitialization.** Does repeated init or a new init manifest reset the
   chain, or does media continue referencing the preceding media manifest?
   What defines a new continuity epoch?

For example, in `init I -> M1 -> M2 -> M3`, a receiver joining with I and M3
does not thereby make I the predecessor of M3: the signed predecessor is M2.
The presence check and the ability to perform the equality check are different.
No `previousManifestUri` retrieval mechanism, null/genesis sentinel, or standard
unknown-continuity result is defined for this method.

## Narrow Draft To Track Existing Work

A separate draft extracts the existing init-rooted policy onto #2631 so it can
be reviewed without the fork's other features:

- `sign_init_segment` records the generated init manifest ID; fresh media
  signing requires that anchor, while explicit media resume remains possible.
  Repeated init signing does not replace an already known init/media predecessor
  or advance the media sequence. To bootstrap a receiver with the first init,
  retain and deliver those original signed init bytes; signing another init is
  not an idempotent byte replay or an implicit chain reset.
- The validator exposes registration of a verified init manifest, and the CLI
  supplies that manifest only after its existing signature/hard-binding checks.
- A present but mismatching first predecessor fails. Missing required metadata
  under this explicitly registered-init profile is distinguished from mismatch.
- Tests cover anchored generation, first-link acceptance/rejection and unchanged
  subsequent media chaining. No placeholder predecessor is invented.

The draft deliberately does not redefine unknown-predecessor acceptance, add
automatic chain-break recovery, or clear media continuity on repeated init. It
contains no VSI session-key changes, vendor gap codes, playback-reset API,
trusted-processor ABI, or downstream pins. It must remain draft while this
discussion is open; this issue is not automatically closed by the tracking PR.

The CLI currently registers the verified init supplied to the command as that
bootstrap. This is intentionally a reviewable policy assumption: a late joiner
may have an active init plus media whose real predecessor is an unseen media
manifest. That scenario can fail under this draft. An init-role or explicit
receiver-state policy must be settled before promoting the proposal; do not
describe this as general midstream/reinitialization conformance.

If a first media segment fails or is rejected before reaching the continuity
validator, no accepted media baseline is established. Later media can then fail
the registered-init comparison repeatedly. This cascading consequence is part
of the unresolved receiver/recovery policy; the draft does not silently adopt
the fork's separate fail-once recovery behavior.

Manifest-method CLI resume skips init re-signing and preserves the original
signed init bytes. When `--init` is supplied on resume, those signed bytes must
already exist in the output directory. A fresh run refuses to overwrite an
existing signed init. SDK callers that sign another init receive newly signed
bytes but retain the prior predecessor; they must not substitute those bytes
for the original bootstrap of an already produced media chain.

An init-only CLI output has no supported cross-process continuation in this
narrow draft: without a signed media predecessor, a fresh invocation refuses
to overwrite init, and `resume_from_segment` cannot restore counters from init.
Keep the live SDK signer alive to sign media later, or stage init and first media
together. If init was already published, do not delete/re-sign it as a recovery
step; a verified init-only restore API with an explicit pre-media publication
boundary is a follow-up, not included here. The output-existence guard does not
prove that a file is signed or belongs to the chain; the validation command
performs those checks. Pre-media init registration can replace an unused anchor,
but does not replace an already observed media predecessor.

## Local Verification

Checked against the pinned #2631 snapshot, with separate per-worktree target
directories (shared-target preliminary results were discarded):

- Rust 1.96.0 live-video SDK tests: 101 passed with Rust-native crypto and
  101 passed with OpenSSL.
- Feature-enabled c2patool: 49 unit tests and 38 integration tests passed.
  Includes resume preserving original init bytes, rejection of media rooted
  in a different signed init, and the documented init-only continuation limit.
- Feature-enabled SDK library and all CLI targets passed Clippy with warnings
  denied; formatting and whitespace checks passed.
- Declared Rust 1.88.0 MSRV library check passed; lockfile unchanged.
- Public rustdoc builds with one pre-existing warning in
  `sdk/src/assertions/session_keys.rs:59` (private `DateT` link). Strict public
  rustdoc therefore remains blocked; documenting private items also exposes
  unrelated baseline documentation failures. No warnings were suppressed.
- Independent static review found the proposal suitable to open as a draft;
  that is not approval of its specification policy or readiness to merge.

No downstream pairing, release, or full cross-platform qualification is claimed.

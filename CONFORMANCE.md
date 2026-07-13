# Conformance contract

## Status

This project targets **`rapp-stack-cubby/macos-arm64-python311/1.0`**. The
local source profile is implemented, but publication, live-host, and public
artifact evidence are not attested. `STACK_LOCK.json` therefore sets
`build_blocked: true` and forbids a conformance claim.

**Working-context note:** `AI_CONTEXT.md` and `docs/canon/` are the current
local authority for implementation work. This document retains earlier target
and audit context; where candidate-source wording differs from current tested
clean-room code, local decisions, `PROVENANCE.json`, and implementation status
win. External repositories are evidence only and need not be fetched.

**No existing public repository currently proves the complete path described
here:** pinned source selection, hardened runtime, all four artifact
transformations, isolated installation, signed twin-chat request and response,
replay-safe operation, and owner-only iMessage delivery on the attested host.
Individual upstreams prove only parts of that path.

## Profile to be implemented

- Public target: `kody-w/rapp-stack-cubby`. Newly authored code is MIT.
- Supported end-to-end profile: arm64 macOS 26.5.1, Python `>=3.11,<3.12`,
  Git 2.50.1, `gh` 2.88.1, Messages.app 26.0, and GitHub Copilot access.
  Other platforms may remain source-compatible, but v1 makes no end-to-end
  claim for them.
- Source runtime: original clean-room implementation under
  `src/rapp_stack_cubby/runtime/`. The pinned Microsoft aibast repository is a
  behavioral/license reference only; no Microsoft or owner-copy runtime file
  is copied or adapted.
- Behavioral pointer:
  [`kody-w/rapp-installer@5fbde17`](https://github.com/kody-w/rapp-installer/tree/5fbde1776a72715935c3d597a9ddfce28a04032b),
  version 0.6.16. It is never a source bundle because its pinned root has no
  license file.
- The only capability endpoint is loopback `POST /chat`. The separately
  configured global controller accepts plain (not twin-signed) but
  bearer-authenticated local control; iMessage uses authenticated challenged
  ingress. Loopback alone is not authentication. Every
  controller-launched or adopted child is signed-only.
- The exact artifact path is:

  ```text
  source repo -> rapp-cubby/1.0 -> rapp-application/1.0
  -> brainstem-egg/2.3-cubby -> isolated installed twin
  ```

  No stage may be skipped or substituted merely because another public
  project also uses `.egg`, “cubby,” or “rapplication.”
- Only the top-level controller agent streams. Every internal `*_agent.py`
  source remains an actual agent inside the rapplication; agents are not
  flattened into controller tools.
- Twin transport uses a complete `rapp-twin-chat/1.0` body inside a signed
  `rapp-commons-event/1.0` wrapper. Requests and responses are signed with
  paired local P-256 keys using exact canonical bytes and low-S P1363.
  Durable replay and idempotency journals bind the paired key, key epoch,
  rappid, nonce, canonical request digest, claim/dispatch phase, and signed
  result. A response binds back to the request nonce, digest, and epoch.
- iMessage v1 is one enrolled owner-only direct conversation through a pinned,
  verified `imsg` binary. Groups and SMS fallback are disabled. Identifiers,
  message content, cursors, journals, and state stay local; file-backed state
  is mode 0600. Local-v1 P-256 private keys may be file-backed only in the
  explicit private root; Keychain is not required for that profile.

## Authority order

Conflicts are resolved in this order:

1. **This release's pinned `STACK_LOCK.json`, `PROVENANCE.json`, and this
   profile.** They select and narrow behavior. Their authority begins only
   when the final release commit is filled and the lock validates.
2. **Twin-chat and wrapper contract:** pinned
   [`NEIGHBORHOOD_PROTOCOL.md`](https://github.com/kody-w/rapp-neighborhood-protocol/blob/44e0c6eb49d619932e645fb9d9b12a5fa37f71b1/NEIGHBORHOOD_PROTOCOL.md)
   from `kody-w/rapp-neighborhood-protocol@44e0c6e` (MIT).
3. **Messaging and iMessage trust contract:** pinned
   [`SPEC.md`](https://github.com/kody-w/rapp-messaging/blob/0586678530bb16215f91104a11737bc69c6f0c48/SPEC.md)
   and
   [`IMESSAGE.md`](https://github.com/kody-w/rapp-messaging/blob/0586678530bb16215f91104a11737bc69c6f0c48/IMESSAGE.md)
   from `kody-w/rapp-messaging@0586678` (MIT).
4. **Runtime behavioral/license reference only:** pinned Microsoft
   [`README.md`](https://github.com/microsoft/aibast-agents-library/blob/29e49d04e830012494198d746734cb19bc6eea60/README.md)
   and
   [`LICENSE`](https://github.com/microsoft/aibast-agents-library/blob/29e49d04e830012494198d746734cb19bc6eea60/LICENSE).
5. **Behavioral evidence only:** the pinned `rapp-installer` 0.6.16 tree.
   Its absent root license makes it ineligible as source.
6. **Secondary evidence:**
   [`openrappter@7b6dbca`](https://github.com/kody-w/openrappter/tree/7b6dbca2cf23f3a21dacc604d2bda34e7e13cd6a)
   and
   [`RAPP@32f1932`](https://github.com/kody-w/RAPP/tree/32f1932f4213ed92dd867325b410f59be535ba19).
   `RAPP` remains reference-only. OpenRappter is reference-only except for the
   six exact MIT iMessage destinations enumerated in `PROVENANCE.json`,
   `SBOM_INPUT.json`, and `NOTICE`.
7. `SOURCE_CENSUS.json` and `docs/research/account-crawl.md` are audit
   evidence, not source bundles and not substitutes for repository-local,
   commit-pinned review.

A repository title, “canonical” claim, index, mirror, or grail link never
overrides direct evidence at the relevant commit. Owner authorization applies
only to original owner-authored material. It does not clear third-party,
forked, copied, generated, or vendored content, and it does not eliminate the
per-file review requirement.

## Known upstream contradictions

- The pinned Microsoft reference advertises remote agent repositories, automatic
  installation of missing Python packages, and endpoints in addition to
  `/chat`. Those behaviors conflict with this profile's fixed dependencies and
  single capability wire.
- The neighborhood protocol describes multiple network transports, permits
  some plaintext `say` traffic, and describes sealed console operation. This
  profile attests loopback only, signs twin traffic and responses, and never
  enables shell, eval, arbitrary console, or mutable remote execution.
- The neighborhood controller pattern focuses on a controller hatching twins.
  This profile additionally fixes the packaging boundary: only the top-level
  controller streams, while internal `*_agent.py` files remain agents.
- The messaging specifications cover non-owner principals and groups. The v1
  iMessage profile deliberately accepts only the enrolled owner's direct
  conversation and has no SMS downgrade.
- The pinned `RAPP` reference reports mixed licensing and `/chat` drift.
  Owner authorization applies only to directly owner-authored material and
  does not remove the per-file provenance gate.
- The account crawl finds incompatible RAPPID widths, cubby records, egg
  families, event conventions, and hatching checks across public projects.
  Shared names are not evidence of wire or artifact compatibility.
- The account crawl also finds historical broad binds, permissive CORS,
  unauthenticated imports, mutable downloads, and request-time package
  installation. None is inherited into this profile.

## Intentional deviations and hardening

The following restrictions are normative, even where an upstream allows more:

1. Bind only to `127.0.0.1` and `::1`; expose only `POST /chat` as a capability.
2. Do not implement `/api/agent`, `/eval`, remote console, arbitrary agent
   import, request-time `pip`, mutable branch execution, wildcard CORS, or an
   unauthenticated mutation path.
3. Keep the runtime original and clean-room. Record and test its local files;
   permit no copied/adapted external runtime source. Track the separate six
   OpenRappter iMessage adaptations per file and preserve MIT notices.
4. Require deterministic artifacts and SHA-256 at every chain node. Verify
   before extraction, reject traversal and links that escape the destination,
   and install into a dedicated workspace and virtual environment.
5. Require paired P-256 signatures for twin traffic and all privileged
   controls; require current epochs, exact canonical wire bytes, low-S
   signatures, and signed responses; fail closed on unknown keys, rappid
   mismatch, escaped/duplicate/malformed claims, stale new dispatch,
   duplicate-conflicting nonces, and journal failure.
6. Permit a duplicate request only when its canonical digest is identical;
   return the already journaled signed result rather than repeat effects.
7. Keep iMessage access read-only on the Messages database and send through the
   verified transport. Do not process groups, attachments without an explicit
   safe policy, other principals, or SMS.
8. Keep keys, identifiers, messages, memories, receipts, and installed twin
   state out of source, artifacts, Pages, logs, and source maps as specified in
   `docs/PUBLIC_PRIVATE_BOUNDARY.md`.

## Non-goals

V1 does not claim:

- Windows, Linux, Intel macOS, containers, LAN, WAN, cloud, Pages, MCP, WebRTC,
  or relay end-to-end attestation;
- compatibility with every public RAPPID, cubby, rapplication, egg, commons,
  neighborhood, or Moment variant;
- group messaging, SMS, arbitrary external DMs, attachments, or a general
  Messages automation service;
- dynamic plugin markets, remote hot-loading, self-modifying agents, package
  installation during chat, shell access, eval, or remote administration;
- migration of private state through public artifacts;
- Microsoft support, endorsement, certification, partnership, or trademark
  affiliation; or
- blanket clearance of any repository or of all code authored by the owner.

## Gates before a conformance claim

All gates are mandatory and fail closed:

1. **Resolve the lock.** Every entry in `STACK_LOCK.json.unresolved` must be
   removed only after its value is filled and independently checked: final
   release SHA/signature, full publication scanner receipt, supported-host
   and owner evidence, public attestations, deployed Pages, and downloaded
   byte equality.
2. **Complete provenance.** Review every imported file at its pinned blob,
   record authorship and license, preserve required notices, prove that no
   excluded or unreviewed file entered the tree, and make `cleared_files`
   exactly match the source manifest.
3. **Prove implementation origin.** Verify the original clean-room runtime
   file manifest and tests, the six separately enumerated OpenRappter
   iMessage adaptations, and the absence of copied/adapted external runtime
   source.
4. **Prove the artifact chain.** Reproducibly build each exact stage, verify
   every digest before use, round-trip the cubby through its egg, reject
   malformed and traversal fixtures, and compare the isolated installed
   manifest with the lock.
5. **Prove the surface.** Tests must show loopback-only binds, the sole
   capability route `POST /chat`, exact-origin or disabled CORS, and rejection
   of prohibited routes, remote imports, auto-pip, mutable downloads, arbitrary
   process execution, and unauthenticated mutation.
6. **Prove agent semantics.** Only the controller stream may stream, and test
   discovery and execution must demonstrate that internal `*_agent.py` files
   remain independent agents inside the rapplication.
7. **Prove twin security.** Positive and negative vectors must cover complete
   inner envelopes, canonical wrappers, paired signatures, signed responses,
   rappid/key/destination binding, stale timestamps, nonce conflict,
   key epochs, duplicate replay, pre/post-dispatch crash recovery, journal
   corruption, controller restart, and exactly-once effects.
8. **Prove owner-only iMessage.** With the pinned binary, demonstrate one
   inbound owner DM, one signed reply, echo suppression, restart recovery, and
   ambiguous-send handling. Prove rejection of groups, other principals, SMS
   fallback, unsupported events, and concurrent writers; prove database
   access remains read-only.
9. **Prove private-state handling.** Verify 0700 private directories, 0600
   file-backed state, approved secret storage, redacted logs, and absence of
   identifiers, content, memories, keys, auth, receipts, and local paths from
   every public surface.
10. **Scan every publication surface.** Pass the required scanners over the
    current tree, full history and refs, recursively unpacked archives, Pages
    output, release assets, source maps, and Actions logs/artifacts as defined
    by `docs/PUBLIC_PRIVATE_BOUNDARY.md`.
11. **Attest the supported host.** Record exact OS/build, architecture, Python,
    Git, `gh`, Messages.app, P-256 dependency, `imsg` binary and code signature,
    and Copilot-access preflight. Run the full end-to-end suite on that host.
12. **Bind the release.** Fill the final 40-hex release commit, regenerate all
    digests and sanitized receipts from that commit, validate both JSON
    documents and their counts, and publish `NOTICE` with the exact per-file
    attribution register.

Passing a component's upstream tests, or demonstrating chat alone, is not a
conformance claim for this profile.

# Public/private publication boundary

Fresh-fork operators must follow the
[owner-only iMessage onboarding tutorial](operations/IMESSAGE_ONBOARDING.md)
before creating any private config or state.

## 1. Enforcement model

The boundary is **default deny**. A file, byte stream, field, log line, build
output, cache, or metadata item is private unless this document positively
allows it. “It contains no obvious secret” is not an allowlist entry.

The policy applies to the repository, every Git object and ref, generated
archives, Pages, releases, Actions, issue attachments, source maps, package
metadata, and any mirror. A path being ignored by Git is not a security
control.

Publication is permitted only when all of these are true:

1. the material matches a public class in §2;
2. its source and license state is allowed by `PROVENANCE.json`;
3. any imported file appears in the final reviewed source manifest;
4. any artifact matches a non-null digest in `STACK_LOCK.json`;
5. all scanners in §7 complete successfully over every applicable surface;
6. a scanner error, inaccessible surface, unknown binary, or unclassified file
   has failed the publication rather than been skipped.

Runtime-private data MUST live outside the repository checkout under one
dedicated state root. The state root and all subdirectories MUST be mode 0700.
File-backed state MUST be mode 0600, created with a restrictive umask before
data is written, and replaced atomically. Shared temporary directories,
repository worktrees, Pages storage, browser storage, and build output
directories are forbidden for private state. Local v1 transport keys may use
unencrypted PKCS8 files only beneath the explicit private state root at mode
0600. Live provider OAuth uses one separately selected absolute, regular,
mode-0600 bounded JSON file with no symbolic-link component. It is created by
`provider-login` or supplied explicitly, never discovered from
Brainstem/OpenRappter, and never copied into runtime/controller state.

## 2. Enforceable classification matrix

| Class | Public allowlist | Private denylist and required placement |
|---|---|---|
| **Source** | Newly authored MIT source explicitly classified `original_new`; adapted MIT files whose exact upstream path/blob, destination, license, modification, and review appear in `PROVENANCE.json`; public schemas; synthetic tests marked as synthetic; these contract documents and their audited census inputs. | Any unreviewed, pointer-only, reference-only, excluded, forked, copied, generated, or vendored source; `.env` values; local configuration; developer scratch data; caches; virtual environments; build directories; private fixtures; absolute local paths. Keep outside the checkout or delete before publication. |
| **Artifacts** | Reproducible `rapp-cubby/1.0`, `rapp-application/1.0`, `brainstem-egg/2.3-cubby`, and release packages only when their exact SHA-256 values are filled in the lock; sanitized SBOM, provenance, signatures, and digest lists. | Installed twins, writable workspaces, virtual environments, caches, journals, databases, runtime configuration, state snapshots, unreviewed source, credentials, or an artifact with a null/mismatched digest. |
| **Pages** | Static documentation and downloads made solely from already-public inputs; synthetic examples; sanitized release metadata. | Runtime state, live chat, control APIs, authentication, secrets, identifiers, messages, memories, receipts, hidden source, private source maps, or any reliance on project-path browser isolation. |
| **Logs** | A deliberately generated release summary containing test names, pass/fail counts, public commit/digest values, tool versions, and redacted error classes. | Raw prompts, responses, tool arguments/results, message text, names, transport identifiers, rappids not explicitly public, tokens, cookies, device codes, environment values, local paths, database rows, stack dumps containing data, or key material. Raw logs remain local mode 0600. |
| **Twin state** | Public schema, empty templates, synthetic fixtures, explicitly public card/facets, and the final release rappid fixture only after it is deliberately approved as public. | Actual soul, memory, agent configuration containing user data, conversation history, trust graph, journals, outbox/inbox, installed workspace, private facets, key references, pairings, and runtime rappid bindings. |
| **Transport keys** | Synthetic/public P-256 JWKs, public key fingerprints, and a release verification key only when deliberately approved. | Every real private key, seed, recovery value, pairing, shared secret, nonce state, or unredacted export. Local v1 private PEM is allowed only in explicit runtime/controller state (0600 beneath 0700); never source, fixtures, logs, artifacts, SBOM input, or browser storage. |
| **iMessage identifiers and content** | Schema documentation and unmistakably synthetic fixtures only. | Account identifiers, participant handles, direct-message identifiers, chat GUIDs, database row identifiers, sender mappings, message bodies, attributed text, attachments, delivery/read state, cursors, and excerpts. Raw identifiers stay only in mode-0600 config; bounded content and HMAC logical state stay only in the private database; the HMAC secret is a separate mode-0600 file. |
| **GitHub/Copilot authentication** | Product names, prerequisite documentation, and a boolean attestation that access succeeded. | GitHub tokens, Copilot tokens, OAuth/device codes, cookies, authorization headers, `gh` configuration, credential-helper output, Keychain references, scopes tied to an account, or token-derived identifiers. |
| **Memories** | Memory schemas, policy documentation, empty examples, and synthetic conformance vectors. | Memory content, embeddings, summaries, provenance events tied to real conversations, asserting principals, audience or trust edges, consent records, model projections, and deletion tombstones. |
| **Receipts** | Sanitized build/conformance receipts containing public commit/digest values, scanner rule-set identities, public tool versions, and pass/fail status. | Message delivery/read receipts, transport acknowledgements tied to a conversation, idempotency/replay records, pairing receipts, consent capabilities, account-scoped attestations, raw scanner findings, or receipts containing paths or identifiers. |
| **Source maps** | Disabled by default. A map may be public only when every mapped source is already public and reviewed, paths are repository-relative, `sourcesContent` contains only allowed public bytes, and the map independently passes all scanners. | Maps containing absolute paths, private or excluded source names/content, build environment details, inline secrets, unreviewed generated code, or `sourcesContent` not byte-matched to the public source. |

No public field may be produced by merely hashing a low-entropy private value
such as a transport identifier. Where local correlation is necessary, use a
keyed local pseudonym; the key and mapping remain private and the pseudonym is
still forbidden from public logs unless explicitly approved.

The public GitHub OAuth client identifier and device verification URI may be
documented because they are not credentials. Device secrets, access/refresh
tokens, and account-bound scopes remain private. A sanitized provider smoke
record may contain only success, exact public model identifier, latency, and
response shape—never prompt/response content, token bytes, or private path.

## 3. Source and provenance controls

The publisher MUST enumerate all outgoing files and classify each one. The
only source inputs eligible for publication are:

- project-original files recorded as `original_new`;
- external files listed in both the selected-source manifest and the matching
  `cleared_files` provenance record;
- generated files whose complete inputs are public/cleared and whose generator
  and deterministic recipe are pinned; and
- synthetic fixtures that contain no transformed real data.

The following are always denied:

- files from `pointer_only`, `reference_only`, or `excluded` entries;
- an unreviewed file from a repository that otherwise has a license;
- archives or generated outputs copied from the grail pointer;
- remote branch contents, mutable URLs, dependency caches, and package-manager
  download caches;
- local `.env` files, credential files, private-key formats, database files,
  WAL or journal files, editor recovery files, crash reports, and OS metadata;
- secrets or private data encoded, compressed, encrypted, split, or renamed;
  encryption is not permission to publish.

An `.env.example` may be public only when every value is an obvious inert
placeholder and the scanner confirms that no value was copied from a real
environment. Filenames, test names, commit messages, and comments are scanned
like file contents.

## 4. Runtime, chat, twin, and iMessage boundary

The v1 server binds only to loopback, which limits exposure but is not
authentication. The separately configured global controller may accept plain
local control pending authenticated iMessage ingress. Every child is
signed-only. All chat remains private runtime data; a signed request does not
make its content public.

Privileged controls require the paired P-256 signature, exact rappid binding,
and replay/idempotency acceptance described by `STACK_LOCK.json`. Authorization
does not permit shell, eval, package installation, arbitrary file mutation,
agent import, or mutable remote execution. Public keys may identify a pairing;
private keys, key references, peer mappings, and journals remain local.

The iMessage adapter accepts only the enrolled owner's direct conversation.
It MUST:

- read the Messages database without writing to it;
- keep all transport identifiers, content, cursor state, GUID mappings,
  outbox/inbox state, echoes, and receipts under the private state root;
- redact content before any operational error is emitted;
- pass only the minimum authorized turn to the model;
- reject groups, other principals, unsupported events, and SMS fallback before
  content reaches agents; and
- avoid identifiers or content in process arguments, environment variables,
  filenames, service labels, metrics, and exception text.

Memory derived from chat or iMessage inherits the most restrictive source
classification. Summarization, embedding, signing, encryption, or deletion
tombstones do not make it public.

## 5. Pages and browser rules

All projects under one Pages origin share a browser-origin security boundary;
project paths do not isolate localStorage, IndexedDB, caches, cookies, service
workers, or credentials. Therefore public Pages output for this project MUST:

- be static and work without GitHub, Copilot, Messages, twin, or local runtime
  credentials;
- store no identity, pairing, message, memory, receipt, or private state in any
  browser storage mechanism;
- register no service worker that can read or retain private state;
- make no request to loopback or private endpoints;
- contain no token input, device-code flow, chat console, or privileged
  control surface;
- use a restrictive Content Security Policy and a fixed asset list; and
- publish source maps only under the narrow allowlist in §2.

Pages builds MUST use the exact staged output as the scanner input. Scanning
only source templates is insufficient.

The local `pages-check` implementation enforces the current static profile:
generated API parity, internal links and assets, project-subpath paths, no
external executable resources, no browser/network APIs, no private patterns,
no unexpected binary/symlink/map, bounded sizes, accessibility structure,
release-pending truth, and immutable workflow pins. A passing local scan does
not replace history, public-log, downloaded-asset, or live-deployment scans.

## 6. Logs, receipts, and diagnostics

Production logging is an allowlist of event name, severity, UTC timestamp,
component, synthetic/local correlation token, and redacted status code. Values
are structured before serialization; post-hoc text replacement is not the
primary control.

The following rules are mandatory:

- never log request or response bodies, model context, tool arguments/results,
  headers, environment, transport payloads, database records, memory values,
  or private exceptions;
- use fixed error messages at trust boundaries and keep sensitive diagnostics
  in a local mode-0600 incident record;
- disable framework access logs that include query strings or user-controlled
  paths;
- do not upload raw test, scanner, coverage, trace, crash, or debug output to
  Actions or releases;
- public receipts contain counts and public hashes only; and
- a failed redaction or serialization step drops the diagnostic, not the
  privacy rule.

## 7. Required scanners and surfaces

Scanner executables, rule sets, and data files MUST themselves be versioned,
source-commit pinned, artifact-hashed, and license-reviewed before becoming
release dependencies. Scanners run with network access disabled after their
inputs are staged.

Every release candidate MUST pass all of these scanner classes:

**Current status:** `publication-scan` implements the complete local,
execution-free scanner matrix below for explicit inputs. Candidate and final
execution remain blocked until the release/Pages tasks supply real Git
history, exact staged/public assets, deployed output, and downloaded completed
Actions log archives. The focused runtime Security agent is not this gate.

1. **Secret and key scanner:** known GitHub/Copilot credential forms, generic
   high-entropy values, OAuth/device material, cookies, authorization headers,
   private-key encodings, seed/recovery material, and suspicious encoded
   blobs.
2. **Identifier and private-content scanner:** transport/account/chat
   identifiers, contact handles, message-like fixtures, real names or
   addresses not deliberately public, database identifiers, local rappid/key
   bindings, memory content, and delivery receipts.
3. **Path and environment scanner:** absolute home/workspace paths, user
   names in paths, environment dumps, hostnames, Keychain references, database
   locations, editor metadata, and build-machine details.
4. **Provenance and license scanner:** every non-original file must match its
   allowed upstream blob and destination; denied provenance states, unknown
   binaries, missing attribution, and unexpected generated/vendor code fail.
5. **Archive scanner:** recursively unpack supported archives and nested eggs,
   wheels, packages, and source bundles; reject traversal, escaping links,
   special files, encrypted members, unsupported formats, excessive nesting,
   and content that cannot be scanned.
6. **Source-map scanner:** parse maps, resolve only relative in-root sources,
   byte-check `sourcesContent`, and apply every other scanner to paths and
   embedded content.

The scanner matrix is mandatory:

| Surface | Required scan |
|---|---|
| **Current tree and index** | All tracked and untracked candidate files, filenames, links, submodule metadata, executable/binary contents, and staged diff. |
| **Full history** | Every object reachable from canonical local branches, tags, and configured remote-tracking branches, plus commit identities/messages and annotated-tag messages. Synthetic pull refs and detached PR merge commits outside that closure are excluded. A clean tip does not excuse a historical leak. |
| **Archives and packages** | The exact final bytes plus every recursively unpacked member, manifest, metadata field, embedded source map, and bundled license/notice. |
| **Pages output** | The exact generated deployment directory, HTML/JS/CSS, static data, maps, headers/configuration, links, and browser-storage/network behavior. |
| **Release assets** | Every asset before upload and the downloaded post-upload bytes; hashes must match the lock and both copies must scan cleanly. |
| **Actions logs and artifacts** | Complete logs for every job and step, annotations, summaries, uploaded artifacts, test/coverage reports, caches selected for publication, and command echo. Scan after completion as well as preventing emission. |

A scan that times out, cannot fetch a required history/ref/log/asset, encounters
an unsupported member, or crashes is a failed gate. Binary allowlisting
requires exact SHA-256, provenance, format-aware inspection, and a narrow
documented reason.

Suppressions MUST name one scanner rule, one exact path or public digest, a
non-secret justification, reviewer, and expiry. Wildcards over directories,
secret classes, or generated outputs are forbidden. Raw findings and scanner
debug logs are private mode 0600; a public receipt may report scanner identity,
input public digest, and pass/fail only.

## 8. Publication procedure

For each candidate release:

1. start from the final pinned commit and a clean, isolated builder;
2. materialize the explicit public allowlist; fail on every extra file;
3. verify source blobs, original/adapted provenance, licenses, and the
   clean-room runtime boundary;
4. build the exact artifact chain with normalized metadata;
5. verify artifact digests before extraction or execution;
6. run `publication-scan --phase candidate` on source, history, generated
   Pages, and recursively unpacked release assets; sign the zero-finding
   receipt and include it and its signature as release assets;
7. stage Pages and release assets without publishing, then scan staged bytes;
8. publish only after the signed candidate gate passes;
9. download and byte-compare public assets, export completed Actions logs, and
   run `publication-scan --phase final` to produce the second signed receipt;
   inspect deployed Pages output; and
10. if any post-publication check fails, invoke §9 immediately.

No workflow may print a secret to mask it later. Secret masking is a secondary
defense, not permission to place private values in Actions.

## 9. Accidental-publication response

Treat any suspected publication as real until disproved.

1. **Contain:** stop the workflow using its exact run control, disable the
   affected Pages deployment, remove release assets and downloadable
   artifacts, close public links, and prevent further mirrors. Do not paste the
   suspect value into an issue or chat.
2. **Preserve privately:** record UTC times, public URLs, commit and asset
   digests, affected surfaces, and minimal forensic copies under the private
   state root. Findings remain mode 0600. Do not collect unrelated message or
   identity data.
3. **Revoke and rotate:** revoke GitHub/Copilot credentials and sessions;
   rotate P-256 transport keys, pairing state, release keys if affected, and
   any exposed dependency or deployment credential. Unpair affected twins and
   change the rappid/key epoch when the binding is exposed. Disable iMessage
   processing while its state is assessed.
4. **Remove:** delete the material from the current tree, rewrite all affected
   reachable history and tags when necessary, purge Pages builds, releases,
   Actions artifacts/caches/logs where the platform permits, and request host
   support/cache removal. Coordinate before force-updating shared refs.
5. **Assume persistence:** deletion from the origin cannot recall clones,
   forks, notifications, caches, model inputs, or downloaded artifacts. A
   published secret is compromised permanently. Exposed message content or a
   stable identifier cannot be made secret again; minimize further use and
   follow the owner's account/transport recovery decision.
6. **Invalidate:** mark affected releases and receipts revoked, remove their
   digests from trusted channels, bump the security/key epoch, and rebuild from
   a clean commit. Never reuse a compromised artifact version.
7. **Verify:** rerun every scanner over the rewritten current tree, all refs
   and objects, archives, staged and deployed Pages, releases, and complete
   Actions output. Check public URLs and asset downloads directly.
8. **Disclose safely:** publish a minimal advisory when users could have
   trusted or downloaded affected bytes. Identify versions, impact, and
   remediation without reproducing private content or identifiers.
9. **Prevent recurrence:** add a narrow regression fixture or scanner rule,
   review why the allowlist failed, and require independent approval before
   restoring publication.

Publication may resume only after rotation/invalidation is complete, all
surfaces pass, and the new release has distinct commit and artifact digests.

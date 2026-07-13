# Security and release profile

The local implementation is default deny: loopback-only service, one
capability route, bounded input/tool rounds, exact local agent loading,
mutation gates, process identity checks, signed paired controller-child
requests/responses, and claim-before-dispatch replay durability.

Transport private state is outside source and artifacts. The file-backed v1
profile uses 0700 directories, 0600 PKCS8 private PEM, and 0644 public JWK
inside private roots. It assumes same-user local processes; it does not claim
protection after that account or private root is compromised. Keychain is not
a v1 requirement.

The focused Security agent's current-tree scan is iterative and deterministic,
never recursive. Lexicographic traversal is capped at 2,048 encountered
entries, 256 opened directories, 500 regular files, 4 MiB total scanned bytes,
512 KiB per file, and depth 64; a caller may lower the file cap. Every
encountered child consumes the entry budget before classification, including
symlinks, special files, stat failures, and entries later rejected by another
bound. Symlinks are never followed, nonregular entries are never opened, and
bounded directory batches are sorted before processing. A reached limit is
reported explicitly with counters and a deterministic truncation reason.

The exact macOS arm64/CPython 3.11 wheels for `cryptography==49.0.0`,
`cffi==2.1.0`, and `pycparser==3.0` are hashed with source, license, and PyPI
metadata. No wheels are committed and no request-time install is allowed.
The explicit fetch command writes only exact size/hash-verified lock URLs to
an external cache. Generated artifacts contain those bytes for offline hatch.

`imsg` v0.12.3 is separately locked to its annotated tag object, peeled
source commit, immutable release asset SHA-256, MIT license blob, Developer ID
authority, Team ID, universal architectures, and expected bundle layout. The
installer accepts the bundled verified local archive, retains strict
signature/team/architecture/layout checks, and never downloads during hatch or
message handling.

Deterministic source/Store/egg/SPDX/provenance/checksum production and isolated
hatch are implemented for repeated builds on the same locked runner image and
toolchain; no cross-host byte claim is made. The checked-in public P-256 anchor
[`RELEASE_TRUST.json`](../../RELEASE_TRUST.json), key ID
`0d7fb1acf871d707bf24b3c298d0f47b1f39f0084e3212ed54c7f0b0abf98b07`,
authenticates one canonical low-S release-manifest signature;
attacker-supplied JWKs are ignored.
Archive verification/extraction and dependency staging stay bound to opened
no-follow descriptors. Installed verification first compares an exhaustive
mode/type/target/hash inventory of source, venv, site-packages, scripts,
distributions and RECORDs, retained archives, imsg, and controller loadout.
It rejects every extra, missing, writable, special, `.pth`, pycache, or changed
entry and performs no installed-Python version probe. The source manifest
excludes itself and final commit; Git/controller verify exact HEAD separately
and the external release sidecar binds revision to artifacts.

The static Pages front door and API are dependency-free, source-generated,
project-subpath safe, browser-state-free, CSP-restricted, and checked against
an exact self-normalized `docs/pages-manifest.json` inventory. Released Pages
requires local pinned-signature verification, every downloaded asset, exact
source HEAD/tree/digest, and GitHub attestation results. Official
CI/Pages/release actions are full-SHA pinned in a reviewed lock. Normal
`main` pushes preserve an existing released site rather than downgrading it.

The dependency-free `publication-scan` command now scans explicit publication
candidates only: current status/tree, reachable Git history, recursively
expanded supported archives, exact Pages, release assets, public redownloads,
and supplied Actions log ZIPs. Corruption, traversal, unsupported archives,
special files, and limits fail closed. Findings contain only rule, public
artifact/member/path, and a digest; passing receipts may be detached-signed by
the pinned release key. Packaging trust is resolved locally. Release remains
blocked on the final exact commit SHA, two signed scan receipts, live owner
enrollment, live Pages, GitHub and supported-host attestation, and public
downloaded-byte equality. Private
keys, pairings, messages, sessions, journals, runtime paths, and installed
state are never release inputs. The protected candidate stage creates one
unchanged prerelease, re-downloads and verifies it, then retains this RC (or
promotes the same prerelease only after final gates) without a source commit.

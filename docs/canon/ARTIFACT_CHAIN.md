# Artifact chain profile

## Exact non-shortcut chain

```text
complete source repository
  -> rapp-cubby/1.0
  -> rapp-application/1.0
  -> deterministic Store intake ZIP + brainstem-egg/2.3-cubby
  -> verified isolated rapp-installed-twin/1.0
  -> controller adopt_install
  -> stopped private instance -> signed-only start
```

The repository is the product and each transform carries the complete
normalized context, source package, runtime, twelve actual child agents, sole
streamable controller, soul, signed twin-chat, owner-only iMessage source and
tutorial, schemas, tests, locks, notices, and operations. The generated
application and egg additionally carry the three locked wheels and signed
imsg archive. Private state and secrets are always absent.

The source `rappid.json` identifies the public product/rapplication. Hatch
creates a distinct private instance RAPPID and binds both identities in the
installed manifest/receipt; adoption creates another controller-owned private
instance identity. Random birth nonces stay local and are never artifact or
receipt fields.

## Source and revision binding

`rapp-release-source-manifest.json` is a deterministic, sorted, per-file
SHA-256/size/mode description of the source tree. It excludes itself, `.git`,
generated release output, caches, bytecode, and private/runtime state. It
cannot embed the commit containing itself. Git/controller separately verify
fetched `HEAD` equals the requested exact commit. The generated, externally signed `release-manifest.json` binds
`source_commit`, Git tree, source-tree digest, and every artifact. Its detached
low-S P-256 signature is accepted only against the checked-in
`RELEASE_TRUST.json`; an embedded JWK has no authority.

Controller repository hatch rejects forbidden top-level runtime/build/dist,
cache, private, and state directories instead of silently skipping them.
Release promotion copies only source-manifest records plus the manifest;
development promotion copies only scanner records. Raw checkouts are never the
running source tree.

## Deterministic artifacts

ZIP members are sorted UTF-8 paths with explicit `SOURCE_DATE_EPOCH`, stored
entries, regular-file types, normalized 0644/0755 modes, no owner/host
metadata, and no directory, link, or special entries. Every payload member is
declared by SHA-256, size, and mode. One no-follow descriptor remains open
through hashing, central-directory validation, semantic verification, and
extraction; each output is rehashed before rename. Verification
rejects traversal, duplicates, unsupported compression, bombs, extra/missing
members, and tamper.

## Status distinctions

| Class | State |
|---|---|
| **Implemented locally** | Pinned release trust/signing/verification, immutable commit staging, descriptor-bound archives/dependencies, exact output, SPDX 2.3, installed RECORD/Python/imsg inventory, isolated hatch/adoption/start, rollback, and identity-bound uninstall. |
| **Development evidence** | Byte-identical repeated signed and unsigned `WORKTREE` builds on the same locked runner/toolchain; signatures verify but remain `development_only:true`, `release:false`. |
| **Not yet claimed** | Final release commit SHA, GitHub/public attestation, live Pages/publication, public re-download equality, and live owner iMessage enrollment. |
| **Unsafe/deprecated** | Shortcutting stages, self-referential commit manifests, mutable downloads, unverified extraction, bundled state/secrets, request-time installation, and treating development output as release. |

See the schemas in `../../schemas/`, decision
`../decisions/artifact-chain.md`, and runbooks
`../operations/PACKAGING_AND_RELEASE.md`,
`../operations/DEPENDENCY_FETCH_AND_VENDOR.md`, and
`../operations/ISOLATED_HATCH.md`.

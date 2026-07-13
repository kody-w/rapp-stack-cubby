# ADR: file-backed transport keys for local v1

**Status:** Accepted and implemented

## Context

The attested target is one same-user local controller and isolated loopback
children. Requiring Keychain would add a platform integration not needed to
prove the local protocol and crash/replay behavior.

## Decision

Store controller and per-twin P-256 private keys as unencrypted PKCS8 PEM only
under explicit private state: directories 0700, private files 0600, public
JWK files 0644 beneath those directories. Creation is atomic and
non-overwriting. Pairings are private. Archive moves keys; rotation and purge
overwrite/unlink retired private files as far as ordinary filesystem
semantics permit and retain only public fingerprints.

## Consequences

Same-user process and private-root compromise are out of scope. No key file is
a source, test fixture, artifact, SBOM, log, or publication input. A broader
deployment requires a new threat model and key-storage ADR.

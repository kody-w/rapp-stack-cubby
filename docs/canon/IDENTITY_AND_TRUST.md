# Identity and trust profile

## Identity and transport authority

The installed identity remains
`rappid:@owner/slug:<64-lowercase-hex>`. It is distinct from transport keys.
The controller owns one stable P-256 transport key and derives:

```text
rappid:@kody-w/rapp-stack-cubby-controller:<sha256-canonical-public-jwk>
```

Each twin owns a unique child transport key and monotonically increasing key
epoch. The controller and child retain
each other's public JWK and exact RAPPID in private pairing state. A valid
signature does not authorize a new action; signed ingress only translates a
strict `say` payload into the existing chat loop.

## File-backed local profile

V1 intentionally uses file-backed unencrypted PKCS#8 `BEGIN PRIVATE KEY` PEM
only in explicit private
runtime/controller state. Directories are 0700, private PEM is 0600, and
public JWK files are 0644 only beneath those private directories. Creation is
atomic and non-overwriting. No key, pairing, replay database, nonce, or
message body is a source, package, SBOM, or publication input.

Keychain is not required for this local v1 profile. Same-user local process
compromise and filesystem access already sufficient to read the configured
private root are out-of-scope threats; broader deployment needs a new threat
model and storage decision.

Archive moves the child key with the twin. Purge overwrites/unlinks the
private file as far as normal filesystem semantics permit and retains only
the public key ID/fingerprint in the tombstone. Guarded `rotate_keys` stops
the child, atomically installs a new child key/pairing, invalidates sessions
and replay trust, records only the retired key ID, securely removes the old
private file, and never auto-starts.

## Fail-closed bindings

The receiver requires the paired public key, matching key ID and current
epoch, exact sender, exact installed destination, equal wrapper/inner
sender/time/kind, exact canonical wire bytes, fresh UTC for new dispatch,
valid low-S raw P1363 signature, and a durable phased replay claim. Responses
require the paired child key, swapped identities, request nonce/digest/epoch,
and fresh UTC on first verification.

Synthetic public vectors under `tests/fixtures/` resolve only the test-fixture
lock. They are explicitly unrelated to a production identity.

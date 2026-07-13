# Twin lifecycle profile

The sole top-level controller owns exact-source hatch and local lifecycle.
Each child has dedicated source, workspace, copied actual agents, data,
generated agents, logs, process identity, signed-chat transport state, and
replay journal.

Implemented actions are `inspect`, `verify`, `adopt_install`, `hatch_repo`,
`list`, `status`, `start`, `stop`, `archive`, `unarchive`, `purge`,
`rotate_keys`, `chat`, and `self_test`. `pack` and `export` remain truthful
pending operations.

Source `rappid.json` is the immutable **product RAPPID**. Egg hatch,
`hatch_repo`, and `adopt_install` each mint a separate private **instance
RAPPID** from product identity, source revision/tree digest, and a local random
birth nonce. The nonce is never persisted or published. All runtime, pairing,
status, confirmation, and iMessage-target operations use the returned instance
RAPPID, never the product RAPPID.

Hatch initializes the stable controller key plus one unique child key and
mutual public pairing. Start repairs only a missing legacy local pairing,
passes every signed-ingress path/identity as fixed argv, and exposes only
`/health` and `/chat`. Archive stops and moves transport state with the twin.
Unarchive never starts automatically.

`rotate_keys` is mutation-gated and idempotent and accepts only an already
stopped twin. It stages a complete replacement child key/pairing, records a
durable switch intent, increments and swaps the generation/key epoch,
invalidates audience sessions and the old replay database, records the old
public key ID, removes the old private key, and leaves the twin stopped.
After the generation switch, retry finishes cleanup and returns that same
generation instead of rotating again.

Purge requires archived state and exact full instance-RAPPID confirmation. It
renames the archive to controller-owned quarantine, durably records that fact,
deletes private/quarantined/session bytes, then commits the tombstone. Cleanup
failure leaves recoverable quarantine without a tombstone; a committed
tombstone is never paired with a restored archive.

Every lifecycle transition has a phase journal with owner PID/start identity
and lease. Under the exclusive controller/instance lock, a retry recovers a
stale transaction by filesystem phase and either finishes forward or rolls
back pre-commit staging. Root, lock, active/archive/purged/staging, workspace,
data, key, session, and state components are opened beneath the resolved
private root without following symlinks.

The separate cubby-egg hatcher verifies the complete offline artifact,
creates a dedicated venv/source/state/workspace/controller loadout, writes
`rapp-installed-twin/1.0`, atomically promotes, and stays stopped. It never
overwrites an identity and rolls staging back on failure. `adopt_install`
accepts only that verified immutable install, records its artifact/source
digests, binds its venv, copies only manifest-listed source, creates new private
pairing/instance identity, and can start those exact bytes without refetching
Git. Start requires an explicit preflighted model, persists `starting`
PID/PGID/OS-start/instance/command identity immediately after spawn, and always
passes signed-only ingress. Signed local controller-child transport is
implemented; live/public attestation and non-loopback control remain future.

`chat` and `self_test` also require action idempotency keys. Before network
send, the controller private transaction journal stores the canonical signed
request bytes, nonce, digest, target, child key, and generation/epoch. A
timeout or restart retries those exact bytes; it never signs a replacement.
Verified `ok` and terminal `rejected` child responses produce one durable
controller result that is replayed exactly. Reusing the key for different
arguments conflicts.

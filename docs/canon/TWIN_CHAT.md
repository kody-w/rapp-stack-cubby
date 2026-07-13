# Signed twin-chat profile

## Implemented request

Controller chat is carried only as the standard outer
`POST /chat` request. Its `user_input` is the canonical JSON serialization of
a signed `rapp-commons-event/1.0`; there is no `/api/agent`, alternate network
route, or direct `perform` shortcut.

The wrapper has exactly `schema`, `from`, `pub`, `alg`, `ts`, `kind`, `body`,
`key_id`, and `sig`. `alg` is `ecdsa-p256`. `body` has exactly the
`rapp-twin-chat/1.0` fields `schema`, `from_rappid`, `to_rappid`, `utc`,
`nonce`, `key_epoch`, `kind`, `payload`, and `facets`. V1 `kind` is `say`;
wrapper and inner sender, timestamp, and kind must be equal. The destination
must be the exact installed twin RAPPID, and `key_epoch` must equal the
current monotonic pairing epoch.

`payload` contains required `user_input`, optional strict
`conversation_history`, and optional `session_id`. Facets are unique,
nonempty strings: at most 16 entries and 128 UTF-8 bytes each. A self-test is
an ordinary signed `say` whose prompt tells the child to call `SelfTest`.

## Cryptographic profile

- ECDSA P-256 with SHA-256 via `cryptography==49.0.0`.
- Private transport loaders accept only exact unencrypted
  `BEGIN PRIVATE KEY` PKCS#8 PEM. SEC1, encrypted PKCS#8, other curves,
  extra PEM blocks, and alternate headers are rejected.
- Public keys are exact JWK objects `{kty,crv,x,y}` with `EC`, `P-256`, and
  32-byte canonical unpadded base64url coordinates.
- The key ID is lowercase SHA-256 hex over the canonical public JWK.
- Wire signatures are exactly 64 raw bytes (`r || s`, P1363), encoded as
  canonical unpadded base64url. `s` must be low-S; high-S equivalents, DER,
  wrong lengths, noncanonical base64url, and invalid points are rejected.
- Signing omits only the top-level `sig`.

The project-owned canonical JSON subset uses UTF-8, lexicographically sorted
keys, compact separators, and preserved Unicode. Floats, NaN/infinity,
duplicate keys, invalid Unicode, and integers outside signed 64-bit are
rejected. General bounds are depth 16, 1 MiB per string, 512 array entries,
256 object members, 4096 nodes, and 2 MiB encoded output. Protocol fields have
smaller limits where their schemas specify them.
For signed request and response text, parsing is not enough: the received
UTF-8 bytes must equal the canonical encoding byte-for-byte before signature
verification. Whitespace, key reordering, and alternate escapes are rejected.
Claim detection decodes JSON string escapes and observes duplicate pairs, so
malformed, duplicate-key, over-depth, or `\u0065`-escaped protocol claims
cannot fall through to ordinary chat.

## Replay and response

Before model or tool dispatch, the child validates the signature, current key
epoch, and pairing, then claims
`(sender_rappid, key_id, key_epoch, nonce)` in its private SQLite journal under
`BEGIN IMMEDIATE`. The row stores the canonical inner-request digest, claim or
dispatch phase, owner PID/lease start/deadline, terminal state, timestamps,
and the exact signed response for completed/rejected rows. Journal metadata is
bound to one epoch; replacing it with an old database fails startup, while an
empty current-epoch database still rejects old-epoch captures.
SQLite uses WAL, `synchronous=FULL`, a busy timeout, mode 0600, and private
directories.

- Same nonce and different digest: conflict.
- An active identical `processing` lease: outer HTTP conflict.
- After an abandoned pre-dispatch claim, the exact persisted request may be
  reclaimed and dispatched only if it is still fresh.
- After the dispatch marker, recovery signs and stores terminal
  `dispatch_ambiguous`; it never redispatches.
- Identical `completed` or `rejected`: return the exact stored signature and
  bytes without provider/tool execution.
- Canonicalization, UTF-8, protocol, signing, response-size, or journal-finish
  errors reached after a claim become a bounded signed rejection. If even that
  cannot be signed/stored, the row becomes durable `failed`; an identical
  retry signs and stores the rejection without redispatch.
- New live requests default to a ±300-second UTC window. A completed exact
  duplicate is journal-retrievable after that window, but cannot redispatch.

The child places canonical `rapp-twin-chat-response/1.0` JSON in the ordinary
outer `/chat.response`. It swaps identities and binds request nonce, canonical
inner digest, key epoch, status, child payload, and child key ID. The
controller accepts both verified `ok` and verified terminal `rejected`
responses. It durably stores the exact outbound request bytes before sending
and the exact controller result after verification. Retrying one action
idempotency key reuses the same bytes, nonce, target, key, and epoch; a
different action request conflicts. A retry after an ambiguous send verifies
the response against that persisted request identity without imposing a new
freshness window. The controller ignores outer
session/log/model claims and trusts only the verified signed payload.
The complete outer response is UTF-8 encoded and checked against the HTTP
response bound before journal completion.

Controller-launched and adopted child runtimes are explicitly `signed_only`;
every plaintext child `/chat` request fails before provider or tool execution.
The separately configured global controller runtime intentionally remains a
plain local control endpoint for now. Loopback is a network-exposure boundary,
not authentication; authenticated global ingress remains owned by the
iMessage repair.

## Boundaries

Loopback does not authenticate callers. Same-user process compromise and a
malicious process already able to read the private data root are out of scope
for this local profile.
Network relays, packaging, and release remain future work. The implemented
owner-only iMessage bridge reaches this transport only through clean global
chat and controller action `chat`; private live enrollment remains gated.

See the three transport schemas, `../operations/TWIN_CHAT_OPERATIONS.md`, and
`../../tests/protocols/`.

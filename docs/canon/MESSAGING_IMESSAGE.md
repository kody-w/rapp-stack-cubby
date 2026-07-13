# Messaging and iMessage profile

## Implemented v1 edge

The only selected messaging edge is one enrolled owner, one exact direct
iMessage self-chat, and one active local writer. `openclaw/imsg` is pinned to
tag `v0.12.3`, its annotated tag object and peeled source commit, immutable
release URL and archive SHA-256, MIT license blob, Team ID, Developer ID
authority, universal executable/helper architectures, and required bundle
layout. `scripts/install-imsg.sh` verifies all of those facts before atomic
promotion.

One supervised child runs fixed argv `[imsg, rpc, --json]` with
`shell=False`. Requests are newline framed, bounded, correlated, and timed
out. Stderr is reduced to fixed diagnostics. A send that was not flushed is
`not_sent`; a flushed send without a proven result is `unknown`. Neither the
RPC client nor bridge automatically retries `send`.
Each child is generation-bound and published before watch startup. Bounded
count/byte/age buffering preserves pre-ack notification order; only the
acknowledged subscription drains, and a matching buffered error restarts the
generation. Timeout shutdown escalates through close, terminate, and kill.

Ingress projects the security-relevant fields from the pinned v0.12.3
`RPCPayloads.swift` message shape and tolerates additive display/metadata
fields such as `chat_name`. Critical identifier, direction, service, account,
participant, attachment, and reaction type changes fail closed. It requires
an exact configured self-chat and discovered account, iMessage service, a
proven owner handle/direction, and no group, attachment-only message,
reaction, SMS, or mention. A keyed logical event claim and its stable
controller idempotency key are durable before worker dispatch. One worker and one
conversation lock preserve owner turn order. Stale first-seen backlog is
dropped.

The private SQLite state uses WAL and full synchronous durability, an fcntl
writer lock plus a database lease, atomic schema migration, an independent
mode-0600 HMAC secret, unresolved-lower-row cursor safety, staged controller
responses, in-flight/backoff state, exact persisted route requests, and outbox
states `staged`, `flushed`, `submitted`, `unknown`, and `not_sent`. Legacy
ambiguous rows migrate into a no-resend quarantine. Raw handles, chat IDs,
GUIDs, and accounts remain only in the
mode-0600 config. The database stores only their HMAC logical IDs. Bounded
message and response content may exist only in that private database.

## Required model route

The bridge never calls a child directly:

```text
Messages.app
→ verified imsg rpc --json
→ owner-only bridge
→ clean global controller POST /chat
→ RappStackCubbyController action=chat
→ signed twin-chat
→ isolated child POST /chat
→ verified signed child response
→ global response
→ exact originating owner self-chat
```

The route instruction supplies the configured exact instance RAPPID, HMAC
audience, and the persisted event idempotency key; the clean controller soul
contains no private target and no model-selected routing. The global runtime
requires the separate mode-0600 controller token. The bridge authenticates the
endpoint with a fresh challenge before sending content, sends a strict bearer,
and verifies request/result/response hashes, signed status, instance RAPPID,
and key epoch. There is no direct-child or model fallback.

Responses are staged before send. Retry/restart reuses the exact route and
idempotency key, so an ambiguous global timeout replays the controller result
without a second child action. A crash after flush recovers to `unknown`
without resend. Returned service and chat fields must match the intended
iMessage target. Submitted outbound GUIDs are HMACed; exact from-me echoes are
classified transactionally, including after claim/restart. Same-text remote
owner turns are retained.

The unavoidable send uncertainty window is between durable `flushed` intent
and receipt of a verifiable `imsg` result. Recovery deliberately converts that
window to `unknown`; it never guesses `not_sent` and never resends. Pinned
`{"ok":true}` send results without an outgoing GUID are also unknown. Their
single from-me text/target echo may be consumed without suppressing a
same-text remote owner turn.

Status is a dedicated mode-0600 content-free file with independent
`transport_ready`, `controller_ready`, and `send_ready` facets. Restart-limit
exhaustion is terminal: the bridge publishes failed status, exits nonzero, and
releases its writer lease for LaunchAgent restart. `transport_ready` requires
recent successful RPC/watch activity, not a stale ready event. The selected
one-record chat/service/account binding is checked on every reconnect and
periodically from the private catalog because pinned live message payloads do
not carry `account_id`.

## Operational boundary

The source, schemas, pinned installer, per-user Aqua LaunchAgent generator,
read-only `IMessage` BasicAgent, and deterministic mocked tests are
implemented. Repository checks never create owner config, start the bridge,
or send a message. Live enrollment waits for an exact released public twin,
private owner values, macOS Full Disk Access and Automation grants, and the
final supported-host attestation.

| Class | State |
|---|---|
| **Profile requirement** | Owner-only ingress, pinned binary, durable cursor/outbox, ambiguous-send recovery, echo suppression, and global-controller-to-signed-twin route. |
| **Implemented now** | Config, RPC supervisor, durable state, bridge/global runner, CLI/service flow, installer, internal inspector agent, schemas, tutorial, and tests. |
| **Live gate** | Private owner enrollment, exact public twin, first real turn, permissions, sleep/wake proof, and final host attestation. |
| **Mapped/reference only** | Groups, external DMs, SMS, attachments, multiple accounts, and cloud messaging. |
| **Unsafe/deprecated** | Caller labels as identity, SMS downgrade, Messages database writes, content in logs/arguments, concurrent writers, mutable downloads, and best-effort resend. |

See `../../schemas/imessage-local-config.schema.json`,
`../../schemas/imessage-status.schema.json`,
`../decisions/owner-only-imessage-v1.md`, and
`../operations/IMESSAGE_ONBOARDING.md`.

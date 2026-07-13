# ADR: owner-only iMessage v1

**Status:** Accepted; implemented locally, live enrollment pending

## Context

General messaging adds principal, group, downgrade, attachment, ordering, and
delivery ambiguity beyond the selected end-to-end proof.

## Decision

V1 accepts one enrolled owner's direct iMessage conversation through one
pinned, verified `imsg` process. Reject groups, SMS fallback, other
principals, and unsupported content before model access. Keep all state local
and route through authenticated clean global chat to controller action `chat`,
which alone forms signed twin-chat. Group aliases by one exact chat record,
require private disambiguation when multiple records match, and bind one
account from the same pinned catalog because live message payloads omit it.
Revalidate that record/account/service on reconnect and periodically. Persist
one HMAC-derived event idempotency key
and exact route before dispatch. Accept a result only when its request,
canonical controller result, exact child response, signed status, instance
RAPPID, and key epoch all verify. A flushed send with no proven result becomes
unknown and is never retried.

## Consequences

The useful end-user path stays narrow and testable. Additive upstream display
fields remain compatible, while schema-critical type changes fail closed.
Ambiguous timeouts and successful sends without a GUID favor no duplicate;
exact or one-shot unknown text/target echoes are classified transactionally,
and terminal transport failure exits for LaunchAgent restart.
It is not a general Messages automation service.

## Verification

`docs/canon/MESSAGING_IMESSAGE.md`, both local schemas, the pinned installer,
privacy policy, and `tests/imessage/` define local implementation. The
fresh-fork onboarding runbook defines the separate live enrollment proof.

# ADR: signed twin-chat through `/chat`

**Status:** Accepted and implemented locally

## Decision

Controller-to-child chat uses a complete `rapp-twin-chat/1.0` body inside a
signed `rapp-commons-event/1.0`, serialized into the child runtime's sole
`POST /chat.user_input`. The child verifies and durably claims before model or
tool dispatch, then signs `rapp-twin-chat-response/1.0` into the ordinary
outer response. Controller trust comes only from that verified signed body.

ECDSA P-256/SHA-256 uses strict unencrypted PKCS#8 keys, low-S raw P1363
signatures, current key epochs, and exact canonical UTF-8 wire bytes.
Completed identical duplicates return the exact stored response. Crash
recovery reclaims only a pre-dispatch claim; a dispatch marker becomes a
signed terminal ambiguous result and never redispatches.

Every child is explicitly signed-only. The separate global controller runtime
remains plain local control pending authenticated iMessage ingress; loopback
itself is not authentication.

## Rejected alternatives

An `/api/agent` route, relay-specific endpoint, direct `perform` shortcut,
plaintext fallback, DER wire signatures, and unsigned responses are rejected.

## Verification

`tests/protocols/`, signed runtime/controller tests, the three wire schemas,
and `docs/operations/TWIN_CHAT_OPERATIONS.md`.

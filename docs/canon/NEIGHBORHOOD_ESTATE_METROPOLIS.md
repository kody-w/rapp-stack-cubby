# Neighborhood, estate, and metropolis profile

## Mapped model

A neighborhood is an admitted set of twins exchanging signed and optionally
sealed Commons events. A relay transports opaque bytes and is not an identity
authority. An estate is an operator-controlled discovery index for twins and
neighborhoods. A metropolis aggregates public discovery across estates.
Discovery metadata is neither private state nor proof that a runtime is
online.

Safe admission requires authenticated public-key exchange, explicit
RAPPID/key binding, audience policy, strong join material, event kind and size
allowlists, signature verification before rendering, freshness and replay
checks, and explicit confidentiality keys. Browser storage under shared
project origins is not an isolation boundary.

## Status distinctions

| Class | State |
|---|---|
| **Profile requirement** | Preserve compatible signed envelope semantics so future transport cannot weaken twin-chat. |
| **Implemented now** | Local schemas and selected twin-chat profile only; no neighborhood service or deployment. |
| **Mapped/reference only** | Peer rooms, residents/relays, sealing, estate indexes, metropolis discovery, and browser invitations. |
| **Unsafe/deprecated** | Weak fixed-salt PINs, rendering before verification, relay-asserted identity, stale IDs, shared-origin secrets, and plaintext privileged events. |
| **Future owner** | No v1 implementation owner; any proposal follows completed `twin-chat` and a new decision/lock update. |

See `SYSTEM_MODEL.md`, `TWIN_CHAT.md`, and `GAP_REGISTER.md`.

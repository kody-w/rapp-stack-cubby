# Twin-chat pairing, rotation, and replay recovery

## Pairing and start

1. Configure an absolute private controller data root and enable guarded
   mutations.
2. Hatch an exact source tree. Hatch creates the stable controller key and a
   unique child key plus mutual public pairing.
3. Start with the fixed Python 3.11 path. The controller passes child private
   key, paired controller JWK/RAPPID, twin RAPPID, current key epoch,
   `--signed-only`, provider timeout, and replay DB as fixed argv.
4. Confirm health, then use controller `chat` or `self_test` with a unique
   action idempotency key; both use signed `POST /chat`.

Never copy pairing/private/replay state into the checkout or diagnostics.

## Rotation

Stop is automatic, but restart is not:

```json
{"action":"rotate_keys","rappid":"<full-rappid>","idempotency_key":"<unique-safe-id>"}
```

Confirm the result is stopped, generation increased, old/new public key IDs
differ, sessions and replay trust were invalidated, and no retired private
file remains. Start explicitly after review.

## Replay recovery

- `completed`/`rejected`: resend the exact signed request to retrieve the
  stored exact response, even after freshness expiry.
- active `processing`: retry later with the same controller action key.
- abandoned claim with no dispatch marker: runtime recovery may reclaim the
  exact request if it is still fresh.
- abandoned row with a dispatch marker: runtime recovery stores a signed
  terminal ambiguous rejection and never redispatches.
- nonce/digest conflict: reject and investigate the sender.
- corrupt/unavailable journal: keep the twin stopped; preserve private state
  for local incident review, rotate keys only after deciding ambiguous effects
  cannot be repeated.

Never edit journal rows, expose nonces/message bodies, reset an epoch, or
turn a dispatch-marked row back into a first claim.

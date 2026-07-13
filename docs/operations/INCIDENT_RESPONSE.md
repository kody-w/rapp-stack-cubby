# Incident response

Treat suspected source, credential, private-data, artifact, signing,
controller, or publication exposure as real until disproved.

1. **Contain:** stop the exact affected process/workflow; disable affected
   publication surfaces and prevent new downloads. Do not paste suspect data
   into issues or chat.
2. **Preserve privately:** record UTC times, public commit/artifact hashes,
   affected classes, and minimal diagnostics under a mode-0700 private root
   with mode-0600 files. Collect no unrelated messages or identifiers.
3. **Revoke/rotate:** revoke affected authentication, signing, pairing, and
   release trust. If the release key is suspect, remove affected assets,
   replace the checked-in public anchor in a separately reviewed source
   revision, and never reuse the old key ID. Disable messaging while assessed.
4. **Remove:** remove current/public bytes, affected assets and deployments,
   and coordinate history/ref cleanup where required. Assume clones and caches
   may persist.
5. **Invalidate:** mark releases and receipts revoked; do not reuse their
   version, commit, identity epoch, key, or artifact digest.
6. **Repair:** add a narrow synthetic regression test/scanner rule and fix the
   failed allowlist or trust transition.
7. **Verify:** rerun all repository, history, nested-secret, descriptor-bound
   archive, installed-inventory, Pages, asset, and workflow scans; run
   `verify-release` against the pinned anchor and compare public downloads with
   the rebuilt exact `SHA256SUMS`.
8. **Disclose safely:** identify affected public versions, impact, and action
   without reproducing private content, identifiers, paths, or secrets.

Resume only after rotation/invalidation, complete clean scans, independent
review, and a distinct exact-commit candidate. For repository-only correctness
failures with no exposure, preserve the same fail-closed approach but avoid
unnecessary private data collection.

For the owner-only iMessage edge, stop the exact LaunchAgent with `--stop` and
confirm it is unloaded before touching its plist. Treat watch-buffer overflow,
subscription errors, restart exhaustion, or chat/account/service rebinding as
a fail-closed transport incident: preserve only content-free status and
timestamps, keep identifiers and message content private, and re-run private
preflight before restart. An unknown send, including `ok=true` without a GUID,
must never be resent; inspect the enrolled chat privately and retain or erase
state according to the onboarding runbook.

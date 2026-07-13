# Repository settings

Nothing in source proves that remote settings are applied. A repository
administrator must run the idempotent verifier after repository creation and
again after policy changes:

```sh
GH_TOKEN="<ADMIN_TOKEN_FROM_PRIVATE_ENVIRONMENT>" \
PYTHON="<ABSOLUTE_PYTHON_311>" \
scripts/configure-repository.sh \
  --repo kody-w/rapp-stack-cubby \
  --main-branch main \
  --reviewer-user-id "$PRIVATE_REVIEWER_DATABASE_ID"
```

Use `--reviewer-team-id "$PRIVATE_TEAM_DATABASE_ID"` instead of, or in
addition to, the user ID. Reviewer database IDs are explicit private
operational inputs and are never committed. The command fails unless every
write can be read back and verified.

The script configures and verifies:

- Pages `build_type=workflow`;
- protected `main`, required `verify`, current-branch checks, review,
  code-owner review, last-push approval, linear history, no force push, and no
  deletion;
- repository immutable releases;
- an active no-bypass tag ruleset that rejects updates and deletion for
  `refs/tags/*`;
- protected `release` and `promotion` environments with required reviewers,
  no self-review, and tag-only `v*` deployment policies.

GitHub editions and organization policy can limit these APIs. Unsupported or
unverifiable settings are a hard failure, not a local substitute.
Candidate/postflight/promotion receipts created after publication are
attested Actions evidence and then verified into released Pages; workflows
never append assets to an immutable published release.

## Protected environment secrets

Set values interactively from a private operator terminal; do not put values
in source, command arguments, logs, issues, or release notes:

```sh
gh secret set RAPP_RELEASE_SIGNING_KEY_PEM \
  --repo kody-w/rapp-stack-cubby --env release
gh secret set RAPP_RELEASE_SIGNING_KEY_PEM \
  --repo kody-w/rapp-stack-cubby --env promotion
gh secret set RAPP_LIVE_PROOF_RECEIPT_JSON \
  --repo kody-w/rapp-stack-cubby --env promotion
gh secret set RAPP_LIVE_PROOF_SIGNATURE_JSON \
  --repo kody-w/rapp-stack-cubby --env promotion
```

The public key in `RELEASE_TRUST.json` must match the environment-scoped
private signer. The live receipt must be sanitized, signed, commit/instance/
Pages-bound, and contain no private identifier or message content. Re-run the
configuration verifier after environment reviewer or deployment-policy
changes. A passing local test only proves the script, never the remote state.

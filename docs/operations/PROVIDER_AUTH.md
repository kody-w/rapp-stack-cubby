# Live provider authentication

## Private boundary

The preferred runtime flow is GitHub's public device authorization through
`provider-login`. Choose one explicit absolute path outside the checkout,
under a mode-0700 private directory. The resulting file is atomically written
at mode 0600 and contains bounded JSON with schema
`rapp-copilot-token/1.0`.

```sh
export RAPP_PROVIDER_DIR="<ABSOLUTE_PRIVATE_ROOT>/provider"
export RAPP_GITHUB_TOKEN_FILE="$RAPP_PROVIDER_DIR/github-token.json"
install -d -m 700 "$RAPP_PROVIDER_DIR"
"$PYTHON_311" -m rapp_stack_cubby provider-login \
  --token-file "$RAPP_GITHUB_TOKEN_FILE"
```

The command displays only GitHub's verification URI and one-time user code.
It never displays the device secret or resulting access/refresh token. Polling
is bounded by interval, `slow_down`, expiry, cancellation, and the selected
timeout. If the returned credential includes a refresh token, refresh it in
place:

```sh
"$PYTHON_311" -m rapp_stack_cubby provider-refresh \
  --token-file "$RAPP_GITHUB_TOKEN_FILE"
```

An existing compatible private JSON file may instead be supplied explicitly.
Legacy JSON is accepted only with `access_token` and optional
`refresh_token`. The file must be absolute, regular, mode 0600, bounded, and
have no symbolic-link component. The runtime never searches Brainstem,
OpenRappter, a home-directory filename, or another repository for it.

`copilot login` authenticates Copilot CLI only; it does not automatically
create or select this runtime's token file. Likewise, `gh auth token` may
return a `gho_` token that cannot use the Copilot exchange. The runtime may
attempt that fallback, but an incompatible exchange fails with guidance to
use `provider-login`. `GITHUB_TOKEN` remains an explicit process-local option;
it is never copied to a token file.

## Exact model preflight

Use the same private file for catalog, preflight, smoke, serve, doctor, and
controller child start:

```sh
"$PYTHON_311" -m rapp_stack_cubby models \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" --json
export RAPP_MODEL="<EXACT_ADVERTISED_CHAT_MODEL>"
"$PYTHON_311" -m rapp_stack_cubby provider-preflight \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL" --json
"$PYTHON_311" -m rapp_stack_cubby provider-smoke \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL" --json
```

Preflight reports only model/catalog status and distinguishes missing
authentication, incompatible `gho_`, absent Copilot entitlement, endpoint
drift, unsupported exact model, and transport failure. There is no model
fallback. The smoke uses a fixed synthetic prompt and tool, mutates no
repository data, and outputs only success, model, latency, and response shape.

The private path may appear only in the fixed child process argument vector.
Neither its bytes nor path may enter source, installed workspaces, controller
state, receipts, logs, generated Pages, or release artifacts. Packaging never
bundles the file; publication scanners fail on credential material.

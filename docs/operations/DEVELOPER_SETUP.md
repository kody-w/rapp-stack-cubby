# Developer setup

## 1. Select only explicit paths

Python must be CPython 3.11. Every mutable directory is outside this checkout;
no command falls back to `HOME`.

```sh
export SOURCE_ROOT="$(pwd -P)"
export PYTHON_BOOTSTRAP="/opt/homebrew/bin/python3.11"
export EXTERNAL_ROOT="<ABSOLUTE_EXTERNAL_ROOT>/rapp-stack-cubby"
export RAPP_VENV="$EXTERNAL_ROOT/venv"
export RAPP_CACHE="$EXTERNAL_ROOT/cache"
export RAPP_WORK="$EXTERNAL_ROOT/work"
export RAPP_INSTALLS="$EXTERNAL_ROOT/installs"
export RAPP_CONTROLLER="$EXTERNAL_ROOT/controller"
install -d -m 700 "$EXTERNAL_ROOT" "$RAPP_CACHE"
```

## 2. Fetch locked inert bytes separately

This is the only networked development dependency step. It fetches exactly the
three locked wheels and pinned `imsg` archive, then verifies size and SHA-256.

```sh
PYTHON="$PYTHON_BOOTSTRAP" \
RAPP_DEPENDENCY_CACHE="$RAPP_CACHE" \
  scripts/fetch-dependencies.sh
```

## 3. Bootstrap offline

The bootstrap verifies the cache before creating the external venv, installs
only exact wheels with `--no-index --require-hashes --no-deps`, and runs
doctor, context, Pages, and repository checks.

```sh
scripts/bootstrap-development.sh \
  --python "$PYTHON_BOOTSTRAP" \
  --venv "$RAPP_VENV" \
  --dependency-cache "$RAPP_CACHE" \
  --work-dir "$RAPP_WORK" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER"
export PYTHON_311="$RAPP_VENV/bin/python"
```

Run offline doctor again at any time:

```sh
PYTHONPATH="$SOURCE_ROOT/src" "$PYTHON_311" -m rapp_stack_cubby doctor \
  --root "$SOURCE_ROOT" \
  --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER"
```

Doctor checks Python 3.11, exact package versions, Git/GitHub CLI presence,
source-manifest freshness, repository status, the verified cache, and
mode-0700 external roots. A dirty development checkout is reported but is not
misrepresented as a candidate.

## 4. Run the complete offline product demo

This command does not publish, enroll iMessage, or send a message. It builds
twice, verifies an ephemeral signed development trust chain, hatches, adopts
installed bytes without Git, starts the explicit attestation child, performs
the signed `SelfTest action=run`, stops, archives/unarchives, proves no orphan,
cleans up, and writes a mode-0600 content-free receipt.

```sh
scripts/demo-product.sh --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER" \
  --receipt "$EXTERNAL_ROOT/demo-receipt.json" \
  --cleanup
```

The development signer and trust file are ephemeral external inputs. They
cannot authorize a candidate or stable release. Normal hatch still requires
the pinned release trust chain.

## 5. Opt in to a live provider

Offline doctor and demo never authenticate to a model provider. Live operation
has no default model: list the current catalog, select one exact advertised
chat-completions model, and preflight it before start. Create one explicit
private token file with the self-contained device flow:

```sh
export RAPP_PROVIDER_DIR="$EXTERNAL_ROOT/provider"
export RAPP_GITHUB_TOKEN_FILE="$RAPP_PROVIDER_DIR/github-token.json"
install -d -m 700 "$RAPP_PROVIDER_DIR"
"$PYTHON_311" -m rapp_stack_cubby provider-login \
  --token-file "$RAPP_GITHUB_TOKEN_FILE"
"$PYTHON_311" -m rapp_stack_cubby models \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" --json
export RAPP_MODEL="<EXACT_ADVERTISED_MODEL_ID>"
"$PYTHON_311" -m rapp_stack_cubby provider-preflight \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL" --json
"$PYTHON_311" -m rapp_stack_cubby doctor \
  --root "$SOURCE_ROOT" \
  --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER" \
  --live \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL"
```

`copilot login` authenticates Copilot CLI, not this runtime's selected token
file. A compatible existing private JSON file may be supplied explicitly;
there is no Brainstem/OpenRappter/home-file search. `gh auth token` remains a
fallback, but an incompatible `gho_` exchange fails with content-free
`provider-login` guidance. See `PROVIDER_AUTH.md`.

The reserved `attestation-self-test/1.0` model is rejected unless
`--attestation-mode offline-self-test` is also explicit on a signed-only child.
It has no network or authentication path and can call only `SelfTest` with
exactly `{"action":"run"}`.

Use `LOCAL_LIFECYCLE.md` for exact authenticated controller commands and
`IMESSAGE_ONBOARDING.md` only after a public candidate is ready for private
owner enrollment.

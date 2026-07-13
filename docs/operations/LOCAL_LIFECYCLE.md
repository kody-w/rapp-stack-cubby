# Local controller/child lifecycle

## 1. Prepare authenticated controller state

Use only explicit mode-0700 roots outside source. The global route has no
model, but it always requires a mode-0600 bearer token.

```sh
export SOURCE_ROOT="$(pwd -P)"
export PYTHON_311="<ABSOLUTE_EXTERNAL_VENV>/bin/python"
export PRIVATE_ROOT="<ABSOLUTE_EXTERNAL_ROOT>/controller"
export CONTROLLER_LOADOUT="$PRIVATE_ROOT/loadout"
export CONTROLLER_DATA="$PRIVATE_ROOT/state"
export GLOBAL_DATA="$PRIVATE_ROOT/runtime"
export CONTROLLER_AUTH_DIR="$PRIVATE_ROOT/auth"
install -d -m 700 "$PRIVATE_ROOT" "$CONTROLLER_DATA" "$GLOBAL_DATA"
"$PYTHON_311" -m rapp_stack_cubby controller-loadout \
  --root "$SOURCE_ROOT" \
  --output-dir "$CONTROLLER_LOADOUT"
"$PYTHON_311" -m rapp_stack_cubby controller-auth \
  --private-dir "$CONTROLLER_AUTH_DIR"
export CONTROLLER_AUTH_TOKEN="$CONTROLLER_AUTH_DIR/controller-auth.token"
```

Start the controller-only runtime in its own terminal. Never omit the token or
load child agents into this process.

```sh
export RAPP_STACK_CONTROLLER_DATA_DIR="$CONTROLLER_DATA"
export RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS=1
PYTHONPATH="$SOURCE_ROOT/src" "$PYTHON_311" -m rapp_stack_cubby serve \
  --soul "$CONTROLLER_LOADOUT/soul.md" \
  --agents-dir "$CONTROLLER_LOADOUT/agents" \
  --data-dir "$GLOBAL_DATA" \
  --root "$SOURCE_ROOT" \
  --principal global-controller \
  --instance-id global-controller \
  --host 127.0.0.1 \
  --port 7071 \
  --controller-route \
  --controller-loadout-root "$CONTROLLER_LOADOUT" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN"
```

All following operations use the exact deterministic CLI, not an instruction
to a model:

```sh
export CONTROLLER_CHAT_URL="<LOOPBACK_GLOBAL_CHAT_URL>"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key inspect-1 \
  inspect
```

## 2. Adopt installed bytes

The supported product route is `hatch-egg -> verify-install -> adopt`. It does
not refetch Git. Save the response in a mode-0600 private file, then extract
the returned controller **instance RAPPID** without printing it. Do not use the
public product RAPPID or the different installed-instance RAPPID.

```sh
export INSTALLED_TWIN="<ABSOLUTE_VERIFIED_INSTALL>"
export ADOPT_RESULT="$PRIVATE_ROOT/adopt-result.json"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key adopt-1 \
  adopt --install-root "$INSTALLED_TWIN" > "$ADOPT_RESULT"
chmod 600 "$ADOPT_RESULT"
export INSTANCE_RAPPID=$(
  "$PYTHON_311" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["controller_result"]["instance_rappid"])' \
    "$ADOPT_RESULT"
)
```

For the signed development demo only, adoption also carries
`--model attestation-self-test/1.0 --attestation-mode offline-self-test
--trusted-development`. That explicit path cannot make an artifact release
eligible.

## 3. Start a live child

There is no default live model. Use the installed Python and installed source
for catalog/auth preflight, then pass that same exact model and external
private token file to start. Follow `PROVIDER_AUTH.md` to create the file;
never place it under the install or controller workspace.

```sh
export INSTALLED_PYTHON="$INSTALLED_TWIN/venv/bin/python"
PYTHONPATH="$INSTALLED_TWIN/source/src" \
  "$INSTALLED_PYTHON" -m rapp_stack_cubby models \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" --json
export RAPP_MODEL="<EXACT_ADVERTISED_MODEL_ID>"
PYTHONPATH="$INSTALLED_TWIN/source/src" \
  "$INSTALLED_PYTHON" -m rapp_stack_cubby provider-preflight \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL" --json
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key start-1 \
  start --rappid "$INSTANCE_RAPPID" --model "$RAPP_MODEL" \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE"
```

The controller re-verifies installed source/runtime digests, starts
`runtime/venv/bin/python` copied from that install, and always adds
`--signed-only`. It validates and passes the external path only in fixed argv;
it does not copy the path or token into workspace, state, receipts, or logs. A
live start performs real provider preflight. The reserved offline provider is
selectable only with both its exact model and explicit attestation mode.

## 4. Deterministic operations

```sh
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key self-test-1 self-test --rappid "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key status-1 status --rappid "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key stop-1 stop --rappid "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key archive-1 archive --rappid "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key unarchive-1 unarchive --rappid "$INSTANCE_RAPPID"
```

Retry only byte-identical arguments with the same idempotency key. Status must
show `runtime_status=stopped` and `healthy=false` after stop.

## 5. Complete local rollback

Archive again before purge, because purge accepts only archived/stopped state.
Then remove the separately verified installed twin:

```sh
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key archive-cleanup archive --rappid "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby controller \
  --url "$CONTROLLER_CHAT_URL" --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key purge-cleanup purge \
  --rappid "$INSTANCE_RAPPID" --confirmation "$INSTANCE_RAPPID"
"$PYTHON_311" -m rapp_stack_cubby uninstall-twin \
  --install-root "$INSTALLED_TWIN" \
  --controller-root "$CONTROLLER_DATA" \
  --product-rappid "$PRODUCT_RAPPID" \
  --instance-rappid "$INSTALLED_INSTANCE_RAPPID" \
  --confirmation "$INSTALLED_INSTANCE_RAPPID"
```

`scripts/rollback-product.sh` composes stop, archive, service/tool uninstall,
purge, installed-twin uninstall, failed-release handling, and previous Pages
artifact redeployment. It never sends an iMessage.

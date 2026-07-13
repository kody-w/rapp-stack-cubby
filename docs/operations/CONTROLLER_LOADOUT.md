# Controller loadout

The loadout contains only the verified top-level controller agent, the clean
target-free global routing soul, and a deterministic manifest. It is
bootstrap metadata, not a package, release artifact, child twin, or signing
boundary.

## Build

Choose a new directory outside the checkout:

```sh
OUT="$(cd .. && pwd -P)/rapp-controller-loadout"
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby \
  controller-loadout --root . --output-dir "$OUT"
```

The command refuses relative paths, symlink components, existing output, and
locations inside or above the repository. It hashes the checked controller
against the generated catalog, copies that source plus `soul.md` atomically,
uses 0700 directories and 0600 files, and verifies both before promotion.
Verification parses the copied controller without executing it, reconstructs
the complete catalog, and checks schema, deterministic profile, actions,
capabilities, dependencies, mutability, catalog/source hashes, soul hash, and
exact inventory. Manifest assertions cannot fabricate controller authority.

## Operate

Start the repository runtime with only the loadout agent directory and soul,
plus explicit controller switches and a separately created private token:

```sh
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby \
  controller-auth --private-dir "$PRIVATE_CONTROLLER_AUTH"
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby serve \
  --soul "$OUT/soul.md" --agents-dir "$OUT/agents" \
  --data-dir "$PRIVATE_DATA" --root "$SOURCE_ROOT" \
  --principal global-controller --instance-id global-controller \
  --host 127.0.0.1 --port 7071 \
  --controller-route --controller-loadout-root "$OUT" \
  --auth-token-file "$PRIVATE_CONTROLLER_AUTH/controller-auth.token"
```

The reserved exact `RAPP_CONTROLLER_ROUTE/1.0` envelope is disabled without
that flag and verified controller-only loadout. When enabled, the runtime
validates canonical tool/action/arguments/idempotency fields, invokes the
controller through the normal registry tool path without a model/provider
decision, and returns the exact child response, canonical controller result,
and content-free request/result/response proof with signed instance/epoch
bindings.
Every other chat request retains normal behavior. There is no perform/control
HTTP endpoint.

Use controller CLI subcommands; they send only `POST /chat`:

```sh
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby controller \
  --url "$LOOPBACK_CHAT_URL" \
  --auth-token-file "$PRIVATE_CONTROLLER_AUTH/controller-auth.token" \
  --idempotency-key inspect-001 inspect
```

Available commands are `inspect`, `verify`, `adopt`, `hatch`, `start`,
`status`, `self-test`, `stop`, `archive`, `unarchive`, `rotate`, and `purge`.
Supply controller configuration through the host's private environment, never
by editing the loadout:

- explicit controller state root outside source;
- mutation enable flag only for intended lifecycle work;
- explicit Python 3.11 executable for child startup;
- exact model on every `start` request (runtime provider preflight is
  mandatory);
- development hatch flag only for non-release exact-tree testing.

All mutating actions need idempotency keys. `pack` and `export` intentionally
return `pending`.

## Verify and dispose

`verify_controller_loadout()` rechecks mode, inventory, manifest, and source
digest. Remove stale loadouts before rebuilding; never merge their private
runtime state back into the repository.

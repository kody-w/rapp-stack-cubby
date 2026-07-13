# Fresh-fork owner-only iMessage onboarding

This runbook builds the implemented local bridge without publishing,
packaging, enrolling a real owner in source, or sending before the released
public twin exists. Keep every value represented by `<PLACEHOLDER>` private.
Never paste transport identifiers, message text, local paths, keys, status
files, or terminal output into an issue, commit, Pages tree, or receipt.

## 1. Supported profile and prerequisites

The supported bridge host is an Apple-silicon Mac running a current supported
macOS release, CPython 3.11, an interactive Aqua login session, Messages.app,
and one active per-user writer. The pinned `imsg` executable is universal
`x86_64+arm64`; its helper is `x86_64+arm64+arm64e`. The project runtime target
and live attestation target remain macOS arm64.

Recommended isolation:

- create a dedicated, non-administrator macOS user for the bridge;
- use a dedicated iMessage account for that user when practical;
- enroll only the owner's exact direct self-chat;
- do not enable groups, external direct messages, SMS fallback, mentions,
  attachments, or reactions;
- do not share the private state root with another user or backup service.

Install Xcode command-line tools, Git, GitHub CLI, and CPython 3.11. Confirm
that the selected Python is exactly 3.11:

```sh
export PYTHON_BOOTSTRAP="<ABSOLUTE_SYSTEM_PYTHON_311>"
"$PYTHON_BOOTSTRAP" -c 'import sys; assert sys.version_info[:2] == (3, 11)'
git --version
gh --version
```

Authenticate GitHub CLI interactively. Do not put a token in an environment
file:

```sh
gh auth login
gh auth status
```

Authentication output is private workstation data.
This GitHub CLI login is only for repository operations. It does not create
the explicit runtime provider token file described in `PROVIDER_AUTH.md`.

## 2. Fork, clone, and verify

Fork through the GitHub UI or CLI, then clone your fork into a new checkout.
Use placeholders in notes and automation:

```sh
gh repo fork "<PUBLIC_SOURCE_REPOSITORY>" --clone
cd "<CHECKOUT>"
export SOURCE_ROOT="$(pwd -P)"
export EXTERNAL_ROOT="<ABSOLUTE_EXTERNAL_ROOT>/rapp-stack-cubby"
export RAPP_VENV="$EXTERNAL_ROOT/venv"
export RAPP_CACHE="$EXTERNAL_ROOT/cache"
export RAPP_WORK="$EXTERNAL_ROOT/work"
export RAPP_INSTALLS="$EXTERNAL_ROOT/installs"
export RAPP_CONTROLLER="$EXTERNAL_ROOT/controller"
install -d -m 700 "$EXTERNAL_ROOT" "$RAPP_CACHE"
PYTHON="$PYTHON_BOOTSTRAP" RAPP_DEPENDENCY_CACHE="$RAPP_CACHE" \
  scripts/fetch-dependencies.sh
scripts/bootstrap-development.sh \
  --python "$PYTHON_BOOTSTRAP" \
  --venv "$RAPP_VENV" \
  --dependency-cache "$RAPP_CACHE" \
  --work-dir "$RAPP_WORK" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER"
export PYTHON_311="$RAPP_VENV/bin/python"
export PYTHONPATH="$SOURCE_ROOT/src"
"$PYTHON_311" -c 'import sys; assert sys.version_info[:2] == (3, 11)'
```

Do not use an unreviewed branch for live messaging. After the exact locked
requirements pass, run the complete source checks:

```sh
PYTHON="$PYTHON_311" scripts/context-check.sh
PYTHON="$PYTHON_311" scripts/check.sh
"$PYTHON_311" -m rapp_stack_cubby verify --root "$SOURCE_ROOT"
```

A passing source check is not a release, package, public twin, or host
attestation. Packaging and publication remain separate future gates.

## 3. Install and verify the pinned transport

Choose an explicit private root outside the checkout:

```sh
export PRIVATE_ROOT="<ABSOLUTE_EXTERNAL_ROOT>/rapp-stack-cubby-live"
export TOOLS_ROOT="$PRIVATE_ROOT/tools"
mkdir -p "$PRIVATE_ROOT"
chmod 700 "$PRIVATE_ROOT"
scripts/install-imsg.sh --root "$TOOLS_ROOT"
scripts/install-imsg.sh --root "$TOOLS_ROOT" --verify
```

The installer has no mutable version fallback. It downloads only the
`openclaw/imsg` release `v0.12.3` asset:

```text
imsg-macos.zip
```

Before extraction it requires SHA-256
`35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2`.
It rejects unsafe archive members, then strictly verifies both signed code
objects, Team ID `Y5PE65HELJ`, executable architectures `x86_64+arm64`, helper
architectures `x86_64+arm64+arm64e`, required bundles, and version `0.12.3`.
The executable signing authority must contain `Developer ID Application:
Peter Steinberger`. Source tag object, peeled source commit, license blob, and
release evidence are immutable in the repository locks.

The download is staged beneath `TOOLS_ROOT`, never in a system temporary
directory. Promotion and link creation are atomic. The installer never uses
`curl | shell`, a mutable release URL, root privileges, or a default home.

## 4. Sign in to Messages and grant macOS privacy access

While logged in as the dedicated Aqua user:

1. Open Messages.app.
2. Sign in to the dedicated iMessage account.
3. Confirm that iMessage, not SMS, is active.
4. Create or locate one direct self-chat for the owner.
5. Send no bridge test yet.

In **System Settings → Privacy & Security → Full Disk Access**, enable the
exact Python 3.11 executable that will run the bridge. Depending on the macOS
version, the signed `imsg` executable may also need to appear. Full Disk
Access permits read-only access to the Messages database; the bridge never
writes that database.

In **System Settings → Privacy & Security → Automation**, allow the selected
Python/`imsg` process to control Messages. The Automation prompt usually
appears only on the first explicit foreground send. Deny any request for a
different executable. Never run the service as root or as a LaunchDaemon.

After changing Full Disk Access, quit and reopen the terminal and Messages.
After changing Automation, stop and restart the foreground bridge.

## 5. Build the clean global controller loadout

The global runtime must load only the controller agent and the supplied clean
router soul. It must not load child agents or a private target:

```sh
export CONTROLLER_LOADOUT="$PRIVATE_ROOT/controller-loadout"
rm -rf "$CONTROLLER_LOADOUT"
"$PYTHON_311" -m rapp_stack_cubby controller-loadout \
  --root "$SOURCE_ROOT" \
  --output-dir "$CONTROLLER_LOADOUT"
```

The loadout contains:

```text
agents/rapp_stack_cubby_agent.py
soul.md
controller-loadout.json
```

The runtime—not the model or soul—accepts the exact canonical
`RAPP_CONTROLLER_ROUTE/1.0` envelope, invokes
`RappStackCubbyController action=chat` through the normal registry path exactly
once, and returns only the verified signed `child.response` plus a content-free
result proof. It does not contain a private target and forbids direct child
calls and plaintext fallback.

Create the controller IPC secret separately so the deterministic loadout stays
byte-for-byte reproducible and secret-free:

```sh
export CONTROLLER_AUTH_DIR="$PRIVATE_ROOT/controller-auth"
"$PYTHON_311" -m rapp_stack_cubby controller-auth \
  --private-dir "$CONTROLLER_AUTH_DIR"
export CONTROLLER_AUTH_TOKEN="$CONTROLLER_AUTH_DIR/controller-auth.token"
"$PYTHON_311" -m rapp_stack_cubby controller-auth \
  --private-dir "$CONTROLLER_AUTH_DIR" --verify-only
```

The directory is mode 0700 and the raw 32-byte token is mode 0600. The command
prints no token bytes.

## 6. Start the clean global controller

Create private controller runtime state:

```sh
export GLOBAL_DATA="$PRIVATE_ROOT/global-runtime"
export CONTROLLER_DATA="$PRIVATE_ROOT/controller-state"
export IMESSAGE_STATE="$PRIVATE_ROOT/imessage/state"
export IMESSAGE_STATUS="$IMESSAGE_STATE/status.json"
mkdir -p "$GLOBAL_DATA" "$CONTROLLER_DATA" "$IMESSAGE_STATE"
chmod 700 "$GLOBAL_DATA" "$CONTROLLER_DATA" "$IMESSAGE_STATE"
printf '%s\n' '{"controller_ready":null,"dropped":0,"failed":0,"heartbeat_at":0,"imsg_version":"0.12.3","lifecycle":"stopped","pending":0,"processed":0,"read_ready":false,"ready":false,"restart_count":0,"send_ready":null,"transport_ready":false}' \
  > "$IMESSAGE_STATUS"
chmod 600 "$IMESSAGE_STATUS"
export RAPP_STACK_CONTROLLER_DATA_DIR="$CONTROLLER_DATA"
export RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS=1
export RAPP_STACK_PYTHON="$PYTHON_311"
```

Start a clean global loopback runtime in a dedicated terminal:

```sh
PYTHONPATH="$SOURCE_ROOT/src" "$PYTHON_311" -m rapp_stack_cubby serve \
  --soul "$CONTROLLER_LOADOUT/soul.md" \
  --agents-dir "$CONTROLLER_LOADOUT/agents" \
  --data-dir "$GLOBAL_DATA" \
  --root "$SOURCE_ROOT" \
  --principal "global-controller" \
  --instance-id "global-controller" \
  --host 127.0.0.1 \
  --port "<GLOBAL_PORT>" \
  --controller-route \
  --controller-loadout-root "$CONTROLLER_LOADOUT" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --imessage-status "$IMESSAGE_STATUS"
```

The runtime exposes only `GET /health` and `POST /chat`. It must bind loopback.
`/chat` requires the strict bearer; `/health` returns only content-free fields
after a fresh HMAC challenge. Do not add credentials to the URL. The global
route is deterministic and performs no provider model selection.

## 7. Hatch and start the exact public twin once released

Do not continue to owner enrollment until all of the following exist:

- an immutable public release commit `<PUBLIC_COMMIT>`;
- its matching release source manifest and deterministic tree digest;
- the public canonical repository URL `<PUBLIC_REPOSITORY>`;
- the public immutable **product RAPPID** in source `rappid.json`;
- a passing supported-host attestation.

Build the egg, run `hatch-egg`, run `verify-install`, then use the controller
CLI `adopt` command through the clean global `/chat`. Record the returned
private `<INSTANCE_RAPPID>`; it is distinct from both the public product
RAPPID and the installed-instance RAPPID. Run controller `start` for exactly
`<INSTANCE_RAPPID>` with `--model "$RAPP_MODEL"` and the explicit external
`--github-token-file "$RAPP_GITHUB_TOKEN_FILE"`. The guarded repository
`hatch` command remains available for exact-commit operation, but development
hatch is not release eligible.

The deterministic control flow is:

```sh
export INSTALLED_TWIN="$PRIVATE_ROOT/installed-twin"
"$PYTHON_311" -m rapp_stack_cubby hatch-egg \
  --egg "<EXACT_RELEASE_EGG>" \
  --egg-sha256 "<EXACT_RELEASE_EGG_SHA256>" \
  --release-manifest "<EXACT_RELEASE_DIRECTORY>/release-manifest.json" \
  --release-manifest-sha256 "<EXACT_RELEASE_MANIFEST_SHA256>" \
  --release-trust "$SOURCE_ROOT/RELEASE_TRUST.json" \
  --release-signature "<EXACT_RELEASE_DIRECTORY>/release-manifest.json.sig" \
  --release-checksums "<EXACT_RELEASE_DIRECTORY>/SHA256SUMS" \
  --install-root "$INSTALLED_TWIN" \
  --python "$PYTHON_311"
"$PYTHON_311" -m rapp_stack_cubby verify-install \
  --install-root "$INSTALLED_TWIN"
export INSTALLED_PYTHON="$INSTALLED_TWIN/venv/bin/python"
"$INSTALLED_PYTHON" -c \
  'import sys; assert sys.version_info[:2] == (3, 11)'

export ADOPT_RESULT="$PRIVATE_ROOT/adopt-result.json"
PYTHONPATH="$INSTALLED_TWIN/source/src" \
"$INSTALLED_PYTHON" -m rapp_stack_cubby controller \
  --url "<LOOPBACK_GLOBAL_CHAT_URL>" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key "<STABLE_PRIVATE_ADOPT_KEY>" \
  adopt --install-root "$INSTALLED_TWIN" > "$ADOPT_RESULT"
chmod 600 "$ADOPT_RESULT"
export INSTANCE_RAPPID=$(
  "$PYTHON_311" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["controller_result"]["instance_rappid"])' \
    "$ADOPT_RESULT"
)

PYTHONPATH="$INSTALLED_TWIN/source/src" \
  "$INSTALLED_PYTHON" -m rapp_stack_cubby models \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" --json
export RAPP_MODEL="<EXACT_ADVERTISED_CHILD_MODEL_ID>"
PYTHONPATH="$INSTALLED_TWIN/source/src" \
  "$INSTALLED_PYTHON" -m rapp_stack_cubby provider-preflight \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE" \
  --model "$RAPP_MODEL" --json
PYTHONPATH="$INSTALLED_TWIN/source/src" \
"$INSTALLED_PYTHON" -m rapp_stack_cubby controller \
  --url "<LOOPBACK_GLOBAL_CHAT_URL>" \
  --auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --idempotency-key "<STABLE_PRIVATE_START_KEY>" \
  start --rappid "$INSTANCE_RAPPID" --model "$RAPP_MODEL" \
  --github-token-file "$RAPP_GITHUB_TOKEN_FILE"
```

Use the installed venv Python for child model checks. Model selection is only
for the isolated child; it never chooses the global controller route. Create
`RAPP_GITHUB_TOKEN_FILE` outside source/install/workspaces using
`PROVIDER_AUTH.md`. `copilot login` does not automatically select a runtime
token file.

Verify the controller reports the isolated child healthy and paired before
initializing the bridge. Preserve no tool result in public logs.

## 8. Initialize the private owner configuration

Choose explicit private paths and keep placeholders out of shell history when
possible:

```sh
export IMESSAGE_ROOT="$PRIVATE_ROOT/imessage"
export IMESSAGE_CONFIG="$IMESSAGE_ROOT/config.json"
export IMESSAGE_STATE="$IMESSAGE_ROOT/state"
export IMSG_BIN="$TOOLS_ROOT/bin/imsg"
mkdir -p "$IMESSAGE_ROOT"
chmod 700 "$IMESSAGE_ROOT"
```

Initialize only after the public twin exists:

```sh
"$PYTHON_311" -m rapp_stack_cubby imessage init \
  --config "$IMESSAGE_CONFIG" \
  --state-dir "$IMESSAGE_STATE" \
  --imsg "$IMSG_BIN" \
  --global-controller-url "<LOOPBACK_GLOBAL_CHAT_URL>" \
  --controller-auth-token-file "$CONTROLLER_AUTH_TOKEN" \
  --target-rappid "<INSTANCE_RAPPID>" \
  --instance-id "<OPAQUE_INSTANCE_ID>" \
  --owner "<OWNER_HANDLE>" \
  --reply-prefix "<OPTIONAL_PREFIX>"
```

Initialization asks the pinned `imsg` for one bounded catalog, silently
matches a non-group iMessage self-chat, and writes its exact chat IDs plus the
account ID from that same record into the mode-0600 config. It groups ID/GUID
aliases by record and requires exactly one matching record, even when several
records use the same account. Multiple matches fail closed and require a
private `--owner-chat` value. Discovery reports only a count, never IDs.
`--account-id` is not needed: the implemented default derives it from the
selected chat.
When supplied as an exceptional cross-check it must exactly match discovery.
If silent discovery
cannot prove the binding, stop and fix Messages login; do not guess. An
operator may constrain discovery with a private
`--owner-chat "<OWNER_SELF_CHAT_ID>"`, but that value must never enter source
or a support transcript.

The exact config schema is `rapp-imessage-config/1.0`. It rejects remote or
credentialed controller URLs, non-absolute state/tool/config paths, symlinked
state, unpinned `imsg`, groups, external DMs, mentions, SMS, attachments,
reactions, and multiple workers.

## 9. Interpret preflight

Run:

```sh
"$PYTHON_311" -m rapp_stack_cubby doctor \
  --root "$SOURCE_ROOT" \
  --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER" \
  --imessage \
  --imessage-config "$IMESSAGE_CONFIG"
"$PYTHON_311" -m rapp_stack_cubby imessage preflight \
  --config "$IMESSAGE_CONFIG"
```

Content-free fields mean:

| Field | Meaning |
|---|---|
| `version_verified` | `imsg --version` is exactly the pinned version. |
| `archive_hash_verified` | private install evidence matches the immutable release/source lock. |
| `codesign_verified` | strict code-signature verification passed for executable and helper. |
| `team_verified` | pinned Team ID and Developer ID authority matched. |
| `architectures_verified` | both code objects contain every required architecture. |
| `layout_verified` | executable, helper, and required bundle files exist. |
| `account_binding_verified` | exact selected chat IDs and one account still match the private catalog. |
| `read_ready` | the process can perform a bounded Messages catalog read; Full Disk Access is effective. |
| `send_ready` | unknown until an explicit real send succeeds; preflight never sends. |
| `error_codes` | content-free remediation categories, never raw stderr. |

Do not continue when `ok` is false.

## 10. Foreground smoke test and first message

Keep the global controller and child running. Start the bridge explicitly:

```sh
"$PYTHON_311" -m rapp_stack_cubby imessage run \
  --config "$IMESSAGE_CONFIG"
```

Starting the bridge subscribes with a durable resume row but sends nothing by
itself. From the exact enrolled self-chat, send one new owner message. Do not
use a group, another account, SMS, an attachment, or a reaction.

The pinned transport may emit watch messages or errors before returning the
subscription response. The supervisor holds a generation-scoped bounded
buffer, acknowledges the subscription, then drains only that exact
subscription in original order. A matching buffered error restarts startup;
old-generation and wrong-subscription events are ignored. The private catalog
account and selected chat/service are revalidated on every reconnect and
periodically before processing resumes.

The required route is:

```text
Messages.app
  → verified imsg rpc --json child
  → owner-only durable bridge
  → clean global POST /chat
  → RappStackCubbyController action=chat
  → signed twin-chat over isolated child POST /chat
  → verified signed child response
  → global response
  → imsg send to the exact originating self-chat
```

Before the POST, the bridge authenticates the configured endpoint with a fresh
HMAC challenge, then sends the bearer and exact persisted route. It accepts a
global result only when the request hash, canonical controller-result hash,
exact child-response hash, verified signed status, exact instance RAPPID, and
key epoch all match. An `agent_logs` completion line alone is insufficient.
A signed terminal rejection is recorded and never sent as ordinary output.
The bridge stages verified child text in its private database before send. No
model-selected or direct-child fallback exists.

For a controlled diagnostic, inspect the one private global `/chat` response
in memory and confirm the completion line, then discard it. Never save model
or message content in a log. Bridge status should show one processed event,
`send_ready=true`, and no pending event. A matching outbound echo is consumed
exactly once; a same-text remote owner turn remains a new turn.

## 11. Install the per-user LaunchAgent

Stop the foreground bridge first. Choose the exact per-user plist path:

```sh
export SERVICE_PLIST="<ABSOLUTE_USER_LIBRARY>/LaunchAgents/dev.rapp-stack-cubby.imessage.plist"
scripts/install-imessage-service.sh \
  --python "$PYTHON_311" \
  --source-root "$SOURCE_ROOT" \
  --config "$IMESSAGE_CONFIG" \
  --plist "$SERVICE_PLIST"
```

Installation writes but does not load or start the service. Inspect the plist:
it must use the fixed Python/config/source paths, `LimitLoadToSessionType=Aqua`,
mode-0600 content-free logs beneath the private state root, and never
`LaunchDaemon`, root, a shell command, or an identifier in arguments.

Start only with an explicit operator action:

```sh
launchctl bootstrap "gui/$(id -u)" "$SERVICE_PLIST"
```

## 12. Health, restart, and sleep/wake

Status never returns IDs, paths, or content:

```sh
"$PYTHON_311" -m rapp_stack_cubby imessage status \
  --config "$IMESSAGE_CONFIG"
```

Healthy means a fresh heartbeat, lifecycle `running`, `ready=true`,
`transport_ready=true`, and neither `controller_ready` nor `send_ready` false
after an attempt. Transport readiness expires without recent successful
RPC/watch activity; a still-set process event is not health evidence. The
child supervisor owns one `imsg rpc --json` process, performs periodic
catalog activity, resubscribes with the unresolved-safe cursor, and uses
bounded restart backoff.
Exhausting the restart limit publishes lifecycle `failed`, exits nonzero, and
releases the writer lease so LaunchAgent can start a fresh process.

For a planned restart:

```sh
launchctl kickstart -k "gui/$(id -u)/dev.rapp-stack-cubby.imessage"
```

After sleep/wake, wait for a fresh heartbeat and `ready=true`. If the pipe was
closed, the supervisor replaces it and resumes. A staged response continues
without another model call. A send that was flushed but lacked a confirmed
result becomes `unknown` and is never retried. Resolve that message manually.

## 13. Troubleshooting

### Full Disk Access

Symptom: `messages_read_unavailable` or `read_ready=false`.

Quit the service, grant Full Disk Access to the exact fixed Python and signed
tool, reopen the Aqua terminal, reopen Messages, and rerun preflight. Do not
grant access to a mutable wrapper.

### Automation

Symptom: the first explicit send is denied while reads succeed.

Open the Automation privacy pane and allow the exact process to control
Messages. Restart the foreground bridge. Never test by bypassing `imsg` or by
adding SMS fallback.

### No exact self-chat

Symptom: silent discovery reports no match.

Confirm Messages login, create a direct self-chat for the owner, and rerun
initialization. Never substitute a display name, group, recent unrelated
chat, or guessed identifier.

### Ambiguous send

Symptom: outbox state `unknown`.

The JSON-RPC request was flushed but a result was not proven. This includes
`{"ok":true}` without an outgoing GUID. The bridge will not resend. One later
from-me echo with the same exact text and target can close the feedback loop;
a same-text remote owner message remains a new turn. Check the exact self-chat
manually, then leave an unrecovered record as unknown for audit or perform a
new owner turn. Never edit the private SQLite database.

### Controller evidence missing

Symptom: `controller_failed`, no outbound send.

Confirm the clean global runtime loaded only the controller loadout and soul,
uses the same private token file, the target child is running, pairing is
valid, and every proof binding matches. Do not accept a completion marker as
authority and do not point the bridge directly at the child.

## 14. Privacy-preserving backup

Stop the bridge before backup. The config contains raw owner/chat identifiers.
The state contains bounded message/response content, HMAC secret, logical
IDs, cursor, staged responses, outbox, and global session. Back up the entire
private iMessage root only to encrypted owner-controlled storage, preserving
0700 directories and 0600 files. Do not back up service logs to a public or
shared destination.

Restore config, state database, WAL companions if present, HMAC secret, and
permissions as one consistent snapshot. Never merge two active writers or
copy this state into another checkout.

## 15. Safe uninstall and retention choices

Stop and remove only the exact LaunchAgent:

```sh
scripts/uninstall-imessage-service.sh \
  --python "$PYTHON_311" \
  --source-root "$SOURCE_ROOT" \
  --config "$IMESSAGE_CONFIG" \
  --plist "$SERVICE_PLIST" \
  --stop
```

Remove only the pinned tool layout:

```sh
scripts/uninstall-imsg.sh --root "$TOOLS_ROOT" --dry-run
scripts/uninstall-imsg.sh --root "$TOOLS_ROOT"
```

Without `--stop`, service uninstall removes only an owned plist whose label is
verified not loaded. With `--stop`, it boots out a loaded agent and verifies
the label is absent before deletion. A nonzero `bootout` is safe only when the
follow-up query proves the agent unloaded; an unknown or still-loaded state
preserves the plist and returns nonzero. The tool uninstaller verifies the
exact evidence, version, install, and four links before deletion; dry run
deletes nothing. It does not remove config, HMAC secret, SQLite state, logs,
controller state, child state, or Messages data.

Choose one private-state policy:

- **retain for restart:** keep config and state encrypted with original modes;
- **retain keys/state but disable:** keep the private root and remove only the
  service/tool;
- **erase bridge history:** after an encrypted backup decision, securely
  remove the entire private iMessage root while the service is stopped;
- **re-enroll:** erase config and state together, then initialize a new opaque
  instance. Do not retain the old HMAC secret with a partially reset database.

Uninstalling the bridge never deletes Messages conversations or the isolated
public twin. Those have separate lifecycle procedures.

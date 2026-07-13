#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RECEIPT=
RELEASE_ACTION=
REPOSITORY=${GITHUB_REPOSITORY:-kody-w/rapp-stack-cubby}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --receipt) RECEIPT=$2; shift 2 ;;
    --release-action) RELEASE_ACTION=$2; shift 2 ;;
    --repo) REPOSITORY=$2; shift 2 ;;
    *) echo "error: unsupported rollback argument: $1" >&2; exit 2 ;;
  esac
done
case "$RECEIPT" in
  /*) ;;
  *) echo "error: --receipt must be an absolute private file" >&2; exit 2 ;;
esac
case "$RELEASE_ACTION" in
  delete|mark-failed) ;;
  *) echo "error: --release-action must be delete or mark-failed" >&2; exit 2 ;;
esac
case "$REPOSITORY" in
  */*) ;;
  *) echo "error: --repo must be OWNER/REPOSITORY" >&2; exit 2 ;;
esac

PYTHON_COMMAND=${PYTHON:-python3}
VALUES=$(
  "$PYTHON_COMMAND" - "$RECEIPT" "$ROOT" <<'PY'
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve()
info = path.lstat()
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or stat.S_IMODE(info.st_mode) != 0o600
):
    raise SystemExit("error: rollback receipt must be a mode-0600 regular file")
resolved = path.resolve(strict=True)
if resolved == root or root in resolved.parents:
    raise SystemExit("error: private rollback receipt cannot be inside source")
value = json.loads(resolved.read_text(encoding="utf-8"))
if set(value) != {
    "controller", "imessage", "installation", "previous_pages",
    "release", "schema"
} or value.get("schema") != "rapp-private-demo-live-receipt/1.0":
    raise SystemExit("error: rollback receipt schema or fields are invalid")
controller = value["controller"]
installation = value["installation"]
imessage = value["imessage"]
release = value["release"]
previous = value["previous_pages"]
if (
    set(controller) != {"python", "rappid", "root", "token_file", "url"}
    or set(installation) != {
        "instance_rappid", "product_rappid", "root"
    }
    or set(imessage) != {"config", "plist", "tools_root"}
    or set(release) != {"tag"}
    or set(previous) != {
        "commit", "manifest_sha256", "promotion_receipt_sha256",
        "promotion_run_id", "tag"
    }
):
    raise SystemExit("error: rollback receipt nested fields are invalid")
rappid = re.compile(
    r"^rappid:@[a-z0-9][a-z0-9-]{0,62}/"
    r"[a-z0-9][a-z0-9-]{0,62}:[0-9a-f]{64}$"
)
if any(
    rappid.fullmatch(item) is None
    for item in (
        controller["rappid"],
        installation["product_rappid"],
        installation["instance_rappid"],
    )
):
    raise SystemExit("error: rollback identities are invalid")
if installation["instance_rappid"] == installation["product_rappid"]:
    raise SystemExit("error: installed product and instance identities collapsed")
tag = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$")
if (
    tag.fullmatch(release["tag"]) is None
    or tag.fullmatch(previous["tag"]) is None
    or re.fullmatch(r"[0-9a-f]{40}", previous["commit"]) is None
    or re.fullmatch(r"[0-9a-f]{64}", previous["manifest_sha256"]) is None
    or re.fullmatch(
        r"[0-9a-f]{64}", previous["promotion_receipt_sha256"]
    ) is None
    or not isinstance(previous["promotion_run_id"], str)
    or not previous["promotion_run_id"].isdigit()
    or not isinstance(controller["url"], str)
    or not controller["url"].startswith(("http://127.0.0.1:", "http://[::1]:"))
):
    raise SystemExit("error: rollback release or controller binding is invalid")
paths = (
    controller["python"],
    controller["token_file"],
    controller["root"],
    installation["root"],
    imessage["config"],
    imessage["plist"],
    imessage["tools_root"],
)
if any(
    not isinstance(item, str)
    or not pathlib.PurePath(item).is_absolute()
    or "\t" in item
    or "\n" in item
    for item in paths
):
    raise SystemExit("error: rollback paths must be explicit absolute paths")
fields = (
    controller["python"],
    controller["url"],
    controller["token_file"],
    controller["rappid"],
    installation["root"],
    installation["product_rappid"],
    installation["instance_rappid"],
    controller["root"],
    imessage["config"],
    imessage["plist"],
    imessage["tools_root"],
    release["tag"],
    previous["tag"],
    previous["commit"],
    previous["manifest_sha256"],
    previous["promotion_receipt_sha256"],
    previous["promotion_run_id"],
)
print("\t".join(fields))
PY
)
TAB=$(printf '\t')
IFS=$TAB read -r \
  PYTHON_PATH CONTROLLER_URL TOKEN_FILE CONTROLLER_RAPPID \
  INSTALL_ROOT PRODUCT_RAPPID INSTALL_RAPPID CONTROLLER_ROOT \
  IMESSAGE_CONFIG IMESSAGE_PLIST IMSG_ROOT RELEASE_TAG \
  PREVIOUS_TAG PREVIOUS_COMMIT PREVIOUS_MANIFEST_SHA \
  PREVIOUS_PROMOTION_SHA PREVIOUS_PROMOTION_RUN_ID <<EOF
$VALUES
EOF

run_controller() {
  KEY=$1
  shift
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$PYTHON_PATH" \
    -m rapp_stack_cubby controller \
    --url "$CONTROLLER_URL" \
    --auth-token-file "$TOKEN_FILE" \
    --idempotency-key "$KEY" \
    "$@"
}

"$ROOT/scripts/resolve-release-tag.sh" --previous \
  "$PREVIOUS_TAG" "$PREVIOUS_COMMIT" >/dev/null
run_controller rollback-stop stop --rappid "$CONTROLLER_RAPPID"
run_controller rollback-archive archive --rappid "$CONTROLLER_RAPPID"

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$PYTHON_PATH" \
  -m rapp_stack_cubby imessage service-uninstall \
  --config "$IMESSAGE_CONFIG" \
  --plist "$IMESSAGE_PLIST" \
  --stop
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$PYTHON_PATH" \
  -m rapp_stack_cubby imessage install-tool \
  --install-root "$IMSG_ROOT" \
  --uninstall

run_controller rollback-purge purge \
  --rappid "$CONTROLLER_RAPPID" \
  --confirmation "$CONTROLLER_RAPPID"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$PYTHON_PATH" \
  -m rapp_stack_cubby uninstall-twin \
  --install-root "$INSTALL_ROOT" \
  --controller-root "$CONTROLLER_ROOT" \
  --product-rappid "$PRODUCT_RAPPID" \
  --instance-rappid "$INSTALL_RAPPID" \
  --confirmation "$INSTALL_RAPPID"

if [ "$RELEASE_ACTION" = delete ]; then
  gh release delete "$RELEASE_TAG" --repo "$REPOSITORY" --yes
else
  gh release edit "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --prerelease \
    --title "FAILED POSTFLIGHT: RAPP Stack CUBBY $RELEASE_TAG" \
    --notes "FAILED POSTFLIGHT. Rollback completed; do not promote or deploy this candidate."
fi

"$ROOT/scripts/resolve-release-tag.sh" --previous \
  "$PREVIOUS_TAG" "$PREVIOUS_COMMIT" >/dev/null
gh workflow run pages.yml \
  --repo "$REPOSITORY" \
  --ref "$PREVIOUS_TAG" \
  -f "release_stage=final" \
  -f "release_tag=$PREVIOUS_TAG" \
  -f "release_commit=$PREVIOUS_COMMIT" \
  -f "release_manifest_sha256=$PREVIOUS_MANIFEST_SHA" \
  -f "promotion_receipt_sha256=$PREVIOUS_PROMOTION_SHA" \
  -f "promotion_run_id=$PREVIOUS_PROMOTION_RUN_ID"
"$ROOT/scripts/resolve-release-tag.sh" --previous \
  "$PREVIOUS_TAG" "$PREVIOUS_COMMIT" >/dev/null

printf 'PASS rollback submitted; verify prior Pages deployment before closure\n'

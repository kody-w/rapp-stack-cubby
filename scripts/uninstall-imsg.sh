#!/bin/bash
set -euo pipefail
umask 077

VERSION="0.12.3"
ARCHIVE_SHA256="35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
SOURCE_COMMIT="dea78a9e9c493740575b03e443041ef5fbd2d463"
ANNOTATED_REF="76585a9e13a33534bec26d5478482efcc238f803"
LICENSE_BLOB="0ae0cb57d8c6c1417f796b39fc0d6a7f2f7c5c39"
AUTHORITY="Developer ID Application: Peter Steinberger"
TEAM_ID="Y5PE65HELJ"
ROOT="${RAPP_IMSG_INSTALL_ROOT:-}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || { echo "error: --root requires a value" >&2; exit 2; }
      ROOT="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    *)
      echo "error: unsupported uninstaller argument" >&2
      exit 2
      ;;
  esac
done

[[ -n "$ROOT" && "$ROOT" == /* && "$ROOT" != "/" && "$ROOT" != *"/../"* ]] || {
  echo "error: provide the exact absolute install root" >&2
  exit 2
}
[[ "$(id -u)" != "0" ]] || {
  echo "error: refuse a root-owned imsg uninstall" >&2
  exit 1
}

reject_symlink_components() {
  local value="$1"
  local current="/"
  local remainder="${value#/}"
  local part
  IFS='/' read -r -a parts <<<"$remainder"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] || continue
    if [[ "$current" == "/" ]]; then
      current="/$part"
    else
      current="$current/$part"
    fi
    [[ ! -L "$current" ]] || {
      echo "error: install root contains a symbolic link" >&2
      return 1
    }
  done
}
reject_symlink_components "$ROOT"

INSTALL_ROOT="$ROOT/imsg/$VERSION"
BIN_DIR="$ROOT/bin"

verify_link() {
  local name="$1"
  local path="$BIN_DIR/$name"
  local expected="../imsg/$VERSION/$name"
  if [[ -L "$path" ]]; then
    [[ "$(readlink "$path")" == "$expected" ]] || {
      echo "error: refuse to remove an unrelated link" >&2
      return 1
    }
  elif [[ -e "$path" ]]; then
    echo "error: refuse to remove a non-link path" >&2
    return 1
  fi
}

for name in \
  "imsg" \
  "imsg-bridge-helper.dylib" \
  "SQLite.swift_SQLite.bundle" \
  "PhoneNumberKit_PhoneNumberKit.bundle"; do
  verify_link "$name"
done

if [[ -e "$INSTALL_ROOT" || -L "$INSTALL_ROOT" ]]; then
  [[ -d "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || {
    echo "error: exact install path is unsafe" >&2
    exit 1
  }
  EVIDENCE="$INSTALL_ROOT/install-evidence.json"
  [[ -f "$EVIDENCE" && ! -L "$EVIDENCE" ]] || {
    echo "error: exact install evidence is unavailable" >&2
    exit 1
  }
  /usr/bin/grep -Fq '"schema": "rapp-imsg-install-evidence/1.0"' "$EVIDENCE" || {
    echo "error: exact install evidence is invalid" >&2
    exit 1
  }
  /usr/bin/grep -Fq "\"archive_sha256\": \"$ARCHIVE_SHA256\"" "$EVIDENCE" || {
    echo "error: exact install evidence does not match the pin" >&2
    exit 1
  }
  /usr/bin/grep -Fq "\"source_commit\": \"$SOURCE_COMMIT\"" "$EVIDENCE" || {
    echo "error: exact install evidence does not match the source pin" >&2
    exit 1
  }
  /usr/bin/grep -Fq "\"annotated_ref\": \"$ANNOTATED_REF\"" "$EVIDENCE" || {
    echo "error: exact install evidence does not match the tag pin" >&2
    exit 1
  }
  /usr/bin/grep -Fq "\"license_blob\": \"$LICENSE_BLOB\"" "$EVIDENCE" || {
    echo "error: exact install evidence does not match the license pin" >&2
    exit 1
  }
  [[ -x "$INSTALL_ROOT/imsg" ]] || {
    echo "error: exact install executable is unavailable" >&2
    exit 1
  }
  [[ "$("$INSTALL_ROOT/imsg" --version 2>/dev/null)" == "$VERSION" ]] || {
    echo "error: exact install version does not match" >&2
    exit 1
  }
  [[ -f "$INSTALL_ROOT/imsg-bridge-helper.dylib" &&
      ! -L "$INSTALL_ROOT/imsg-bridge-helper.dylib" ]] || {
    echo "error: exact install helper is unavailable" >&2
    exit 1
  }
  [[ -f "$INSTALL_ROOT/SQLite.swift_SQLite.bundle/PrivacyInfo.xcprivacy" &&
      -f "$INSTALL_ROOT/PhoneNumberKit_PhoneNumberKit.bundle/PhoneNumberMetadata.json" ]] || {
    echo "error: exact install bundle layout is unavailable" >&2
    exit 1
  }
  /usr/bin/codesign --verify --strict --verbose=2 \
    "$INSTALL_ROOT/imsg" >/dev/null 2>&1 || {
    echo "error: exact install executable signature is invalid" >&2
    exit 1
  }
  /usr/bin/codesign --verify --strict --verbose=2 \
    "$INSTALL_ROOT/imsg-bridge-helper.dylib" >/dev/null 2>&1 || {
    echo "error: exact install helper signature is invalid" >&2
    exit 1
  }
  executable_signature="$(/usr/bin/codesign -dv --verbose=4 "$INSTALL_ROOT/imsg" 2>&1)"
  helper_signature="$(/usr/bin/codesign -dv --verbose=4 "$INSTALL_ROOT/imsg-bridge-helper.dylib" 2>&1)"
  /usr/bin/grep -Fq "Authority=$AUTHORITY" <<<"$executable_signature" || {
    echo "error: exact install authority is invalid" >&2
    exit 1
  }
  /usr/bin/grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$executable_signature" || {
    echo "error: exact install Team ID is invalid" >&2
    exit 1
  }
  /usr/bin/grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$helper_signature" || {
    echo "error: exact install helper Team ID is invalid" >&2
    exit 1
  }
  executable_arches="$(/usr/bin/lipo -archs "$INSTALL_ROOT/imsg")"
  helper_arches="$(/usr/bin/lipo -archs "$INSTALL_ROOT/imsg-bridge-helper.dylib")"
  for architecture in x86_64 arm64; do
    [[ " $executable_arches " == *" $architecture "* ]] || {
      echo "error: exact install executable architecture is invalid" >&2
      exit 1
    }
  done
  for architecture in x86_64 arm64 arm64e; do
    [[ " $helper_arches " == *" $architecture "* ]] || {
      echo "error: exact install helper architecture is invalid" >&2
      exit 1
    }
  done
else
  for name in \
    "imsg" \
    "imsg-bridge-helper.dylib" \
    "SQLite.swift_SQLite.bundle" \
    "PhoneNumberKit_PhoneNumberKit.bundle"; do
    [[ ! -L "$BIN_DIR/$name" ]] || {
      echo "error: refuse to remove an unverified stale install link" >&2
      exit 1
    }
  done
  printf '{"dry_run":%s,"removed":false,"verified":true,"version":"%s"}\n' \
    "$([[ "$DRY_RUN" == "1" ]] && printf true || printf false)" "$VERSION"
  exit 0
fi

if [[ "$DRY_RUN" == "1" ]]; then
  printf '{"dry_run":true,"removed":false,"verified":true,"version":"%s"}\n' "$VERSION"
  exit 0
fi

for name in \
  "imsg" \
  "imsg-bridge-helper.dylib" \
  "SQLite.swift_SQLite.bundle" \
  "PhoneNumberKit_PhoneNumberKit.bundle"; do
  path="$BIN_DIR/$name"
  [[ ! -L "$path" ]] || /bin/rm "$path"
done
[[ ! -d "$INSTALL_ROOT" ]] || /bin/rm -rf "$INSTALL_ROOT"

/bin/rmdir "$ROOT/imsg" 2>/dev/null || true
/bin/rmdir "$BIN_DIR" 2>/dev/null || true
printf '{"removed":true,"version":"%s"}\n' "$VERSION"

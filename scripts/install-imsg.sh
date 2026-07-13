#!/bin/bash
# Adapted from kody-w/openrappter scripts/install-imsg.sh, commit
# 7b6dbca2cf23f3a21dacc604d2bda34e7e13cd6a, blob
# a6e3726428ce4fb0eda8ad187e0c57da977b3df1 (MIT).
set -euo pipefail
umask 077

VERSION="0.12.3"
URL="https://github.com/openclaw/imsg/releases/download/v0.12.3/imsg-macos.zip"
ARCHIVE_SHA256="35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
ANNOTATED_REF="76585a9e13a33534bec26d5478482efcc238f803"
SOURCE_COMMIT="dea78a9e9c493740575b03e443041ef5fbd2d463"
LICENSE_BLOB="0ae0cb57d8c6c1417f796b39fc0d6a7f2f7c5c39"
AUTHORITY="Developer ID Application: Peter Steinberger"
TEAM_ID="Y5PE65HELJ"
ROOT="${RAPP_IMSG_INSTALL_ROOT:-}"
VERIFY_ONLY=0
ARCHIVE_INPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || { echo "error: --root requires a value" >&2; exit 2; }
      ROOT="$2"
      shift 2
      ;;
    --verify)
      VERIFY_ONLY=1
      shift
      ;;
    --archive)
      [[ $# -ge 2 ]] || { echo "error: --archive requires a value" >&2; exit 2; }
      ARCHIVE_INPUT="$2"
      shift 2
      ;;
    *)
      echo "error: unsupported installer argument" >&2
      exit 2
      ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || {
  echo "error: imsg requires macOS" >&2
  exit 1
}
[[ "$(id -u)" != "0" ]] || {
  echo "error: refuse a root-owned imsg install" >&2
  exit 1
}
[[ -n "$ROOT" && "$ROOT" == /* && "$ROOT" != "/" && "$ROOT" != *"/../"* ]] || {
  echo "error: provide an explicit absolute private install root" >&2
  exit 2
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
mkdir -p "$ROOT"
chmod 700 "$ROOT"

for command in /usr/bin/shasum /usr/bin/unzip /usr/bin/codesign /usr/bin/lipo /usr/bin/find /bin/mv; do
  [[ -x "$command" ]] || {
    echo "error: a required macOS verifier is unavailable" >&2
    exit 1
  }
done
if [[ -z "$ARCHIVE_INPUT" ]]; then
  [[ -x /usr/bin/curl ]] || {
    echo "error: curl is unavailable" >&2
    exit 1
  }
else
  [[ "$ARCHIVE_INPUT" == /* && -f "$ARCHIVE_INPUT" && ! -L "$ARCHIVE_INPUT" ]] || {
    echo "error: --archive requires an absolute regular local zip" >&2
    exit 2
  }
  reject_symlink_components "$ARCHIVE_INPUT"
fi

INSTALL_PARENT="$ROOT/imsg"
INSTALL_ROOT="$INSTALL_PARENT/$VERSION"
BIN_DIR="$ROOT/bin"

has_arches() {
  local file="$1"
  shift
  local arches
  local expected
  arches="$(/usr/bin/lipo -archs "$file")"
  for expected in "$@"; do
    [[ " $arches " == *" $expected "* ]] || return 1
  done
}

signature_for() {
  /usr/bin/codesign -dv --verbose=4 "$1" 2>&1
}

validate_install() {
  local candidate="$1"
  local executable="$candidate/imsg"
  local helper="$candidate/imsg-bridge-helper.dylib"
  local executable_signature
  local helper_signature
  [[ -x "$executable" ]] || return 1
  [[ -f "$helper" && ! -L "$helper" ]] || return 1
  [[ -f "$candidate/SQLite.swift_SQLite.bundle/PrivacyInfo.xcprivacy" ]] || return 1
  [[ -f "$candidate/PhoneNumberKit_PhoneNumberKit.bundle/PhoneNumberMetadata.json" ]] || return 1
  [[ -f "$candidate/install-evidence.json" && ! -L "$candidate/install-evidence.json" ]] || return 1
  /usr/bin/codesign --verify --strict --verbose=2 "$executable" >/dev/null 2>&1 || return 1
  /usr/bin/codesign --verify --strict --verbose=2 "$helper" >/dev/null 2>&1 || return 1
  executable_signature="$(signature_for "$executable")"
  helper_signature="$(signature_for "$helper")"
  /usr/bin/grep -Fq "Authority=$AUTHORITY" <<<"$executable_signature" || return 1
  /usr/bin/grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$executable_signature" || return 1
  /usr/bin/grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$helper_signature" || return 1
  has_arches "$executable" x86_64 arm64 || return 1
  has_arches "$helper" x86_64 arm64 arm64e || return 1
  [[ "$("$executable" --version 2>/dev/null)" == "$VERSION" ]] || return 1
  /usr/bin/grep -Fq "\"archive_sha256\": \"$ARCHIVE_SHA256\"" "$candidate/install-evidence.json" || return 1
  /usr/bin/grep -Fq "\"source_commit\": \"$SOURCE_COMMIT\"" "$candidate/install-evidence.json" || return 1
  /usr/bin/grep -Fq "\"annotated_ref\": \"$ANNOTATED_REF\"" "$candidate/install-evidence.json" || return 1
  /usr/bin/grep -Fq "\"license_blob\": \"$LICENSE_BLOB\"" "$candidate/install-evidence.json" || return 1
}

link_one() {
  local name="$1"
  local target="../imsg/$VERSION/$name"
  local destination="$BIN_DIR/$name"
  local staged="$BIN_DIR/.${name//\//_}.link.$$"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -L "$destination" && "$(readlink "$destination")" == "$target" ]] || {
      echo "error: refuse to replace an unrelated install link" >&2
      return 1
    }
    return 0
  fi
  /bin/ln -s "$target" "$staged"
  /bin/mv "$staged" "$destination"
}

link_install() {
  mkdir -p "$BIN_DIR"
  chmod 700 "$BIN_DIR"
  link_one "imsg"
  link_one "imsg-bridge-helper.dylib"
  link_one "SQLite.swift_SQLite.bundle"
  link_one "PhoneNumberKit_PhoneNumberKit.bundle"
}

if validate_install "$INSTALL_ROOT"; then
  link_install
  printf '{"installed":true,"verified":true,"version":"%s"}\n' "$VERSION"
  exit 0
fi

if [[ "$VERIFY_ONLY" == "1" ]]; then
  echo "error: pinned imsg verification failed" >&2
  exit 1
fi
[[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || {
  echo "error: refuse to overwrite an invalid existing install" >&2
  exit 1
}

WORK_ROOT="$ROOT/.imsg-work-$$-$RANDOM"
[[ ! -e "$WORK_ROOT" ]] || {
  echo "error: installer work path collision" >&2
  exit 1
}
mkdir "$WORK_ROOT"
chmod 700 "$WORK_ROOT"
cleanup() {
  /bin/rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

if [[ -n "$ARCHIVE_INPUT" ]]; then
  ARCHIVE="$ARCHIVE_INPUT"
else
  ARCHIVE="$WORK_ROOT/imsg-macos.zip"
  /usr/bin/curl \
    --fail \
    --location \
    --proto '=https' \
    --silent \
    --show-error \
    --output "$ARCHIVE" \
    "$URL"
fi

ACTUAL_SHA="$(/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}')"
[[ "$ACTUAL_SHA" == "$ARCHIVE_SHA256" ]] || {
  echo "error: pinned imsg archive checksum mismatch" >&2
  exit 1
}

while IFS= read -r entry; do
  [[ -n "$entry" ]] || {
    echo "error: imsg archive contains an empty path" >&2
    exit 1
  }
  case "$entry" in
    /*|*\\*|../*|*/../*|*/..|[A-Za-z]:*)
      echo "error: imsg archive contains an unsafe path" >&2
      exit 1
      ;;
  esac
done < <(/usr/bin/unzip -Z1 "$ARCHIVE")

EXTRACTED="$WORK_ROOT/extracted"
mkdir "$EXTRACTED"
/usr/bin/unzip -q "$ARCHIVE" -d "$EXTRACTED"
[[ -z "$(/usr/bin/find "$EXTRACTED" -type l -print -quit)" ]] || {
  echo "error: imsg archive contains a symbolic link" >&2
  exit 1
}

cat >"$EXTRACTED/install-evidence.json" <<EOF
{
  "annotated_ref": "$ANNOTATED_REF",
  "archive_sha256": "$ARCHIVE_SHA256",
  "license_blob": "$LICENSE_BLOB",
  "schema": "rapp-imsg-install-evidence/1.0",
  "source_commit": "$SOURCE_COMMIT",
  "version": "$VERSION"
}
EOF
chmod 600 "$EXTRACTED/install-evidence.json"
chmod 755 "$EXTRACTED/imsg"

validate_install "$EXTRACTED" || {
  echo "error: downloaded imsg failed signature, architecture, or layout verification" >&2
  exit 1
}

mkdir -p "$INSTALL_PARENT"
chmod 700 "$INSTALL_PARENT"
/bin/mv "$EXTRACTED" "$INSTALL_ROOT"
link_install
validate_install "$INSTALL_ROOT" || {
  echo "error: promoted imsg install failed verification" >&2
  exit 1
}

printf '{"installed":true,"verified":true,"version":"%s"}\n' "$VERSION"

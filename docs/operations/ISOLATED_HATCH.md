# Isolated cubby egg hatch

## Production hatch

Use an externally verified egg digest, signed sidecar, pinned public trust, new
external install path, and exact CPython 3.11. Hatch has no network.

```sh
export PYTHON_311="<ABSOLUTE_EXTERNAL_VENV>/bin/python"
export RELEASE_DIR="<ABSOLUTE_RELEASE_DIRECTORY>"
export INSTALL_ROOT="<ABSOLUTE_NEW_INSTALL>"
export EGG_SHA256="<EXACT_64_HEX>"
export MANIFEST_SHA256="<EXACT_64_HEX>"
PYTHONPATH=src "$PYTHON_311" -m rapp_stack_cubby verify-release \
  --release-manifest "$RELEASE_DIR/release-manifest.json" \
  --release-manifest-sha256 "$MANIFEST_SHA256" \
  --trust "$(pwd -P)/RELEASE_TRUST.json" \
  --signature "$RELEASE_DIR/release-manifest.json.sig" \
  --checksums "$RELEASE_DIR/SHA256SUMS" \
  --source-root "$(pwd -P)"
PYTHON="$PYTHON_311" \
RAPP_EGG="$RELEASE_DIR/rapp-stack-cubby.egg" \
RAPP_EGG_SHA256="$EGG_SHA256" \
RAPP_RELEASE_MANIFEST="$RELEASE_DIR/release-manifest.json" \
RAPP_RELEASE_MANIFEST_SHA256="$MANIFEST_SHA256" \
RAPP_RELEASE_TRUST="$(pwd -P)/RELEASE_TRUST.json" \
RAPP_INSTALL_ROOT="$INSTALL_ROOT" \
  scripts/hatch.sh
PYTHONPATH=src "$PYTHON_311" -m rapp_stack_cubby verify-install \
  --install-root "$INSTALL_ROOT"
```

Production hatch rejects unsigned and development output. It verifies every
archive member before extraction; installs bundled hash-locked wheels with no
index; verifies/installs the pinned signed `imsg`; inventories wheel RECORD,
Python, source, loadout, and inert inputs; mints a private installed-instance
RAPPID; writes mode-0600 manifests/receipt; and atomically promotes without
starting.

## Explicit trusted development hatch

The one-command demo creates an ephemeral external P-256 development trust,
builds twice, verifies that signed `WORKTREE` sidecar, and alone supplies
`--trusted-development`. This flag accepts only `signed:true`,
`development_only:true`, `release:false`; it cannot use the pinned release
identity or authorize publication.

```sh
scripts/demo-product.sh --python "$PYTHON_311" \
  --work-dir "<ABSOLUTE_EXTERNAL_WORK>" \
  --dependency-cache "<ABSOLUTE_VERIFIED_CACHE>" \
  --install-dir "<ABSOLUTE_EXTERNAL_INSTALL_PARENT>" \
  --controller-dir "<ABSOLUTE_EXTERNAL_CONTROLLER_PARENT>" \
  --receipt "<ABSOLUTE_EXTERNAL_RECEIPT>" \
  --cleanup
```

## Installed bytes are running bytes

After `verify-install`, use `controller adopt --install-root`. Adoption
re-verifies and copies only manifest-bound installed source plus the installed
venv into controller-owned state. Start executes that copied
`runtime/venv/bin/python`; neither adopt nor start fetches Git.

The exact flow and private returned-instance extraction are in
`LOCAL_LIFECYCLE.md`:

```text
verify-release -> verify-artifact -> hatch-egg -> verify-install
-> authenticated controller adopt -> returned instance RAPPID
-> explicit model/mode start -> signed self-test -> stop
```

## Removal

Stop, archive, and purge the controller instance before uninstall so no
controller JSON still references the installation.

```sh
PYTHONPATH=src "$PYTHON_311" -m rapp_stack_cubby uninstall-preview \
  --install-root "$INSTALL_ROOT"
PYTHONPATH=src "$PYTHON_311" -m rapp_stack_cubby uninstall-twin \
  --install-root "$INSTALL_ROOT" \
  --controller-root "<ABSOLUTE_CONTROLLER_STATE>" \
  --product-rappid "$PRODUCT_RAPPID" \
  --instance-rappid "$INSTALLED_INSTANCE_RAPPID" \
  --confirmation "$INSTALLED_INSTANCE_RAPPID"
```

The real uninstall identity-checks, quarantines, deletes, and leaves a
content-free mode-0600 journal. It refuses arbitrary paths, live processes,
and retained controller references.

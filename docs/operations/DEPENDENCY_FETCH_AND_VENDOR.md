# Dependency fetch and vendor operation

## Boundary

Source commits no wheels or imsg archive. `DEPENDENCY_LOCK.json` is the only
download authority: exactly three macOS arm64/CPython 3.11 wheels and one
signed imsg archive, each with immutable URL, size, and SHA-256.

## Fetch

```sh
PYTHON=/absolute/python3.11 \
RAPP_DEPENDENCY_CACHE=/absolute/external/cache \
  scripts/fetch-dependencies.sh
```

The cache must be absolute and outside the checkout. Existing mismatched files
are never replaced. Partial files are removed on failure. Downloads are inert:
the command does not import, install, unzip, or execute them.

## Verify and consume

`build` re-verifies all four cache files before staging. It places wheels under
`wheelhouse/` and the archive under `vendor/imsg/` only inside generated Store
and egg artifacts. Hatch invokes pip with `--no-index --find-links
--require-hashes` and gives `install-imsg.sh` the verified local
`--archive`; no implicit download is allowed.

Delete the external cache normally when no longer needed. Never copy it into
source or private runtime state.

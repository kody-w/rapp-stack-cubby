# Repository verification

## Full local gate

```sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/check.sh
```

The gate:

1. requires Python 3.11;
2. compares generated context and agent/controller catalogs with source;
3. validates all context and static API paths, schemas, references, examples, capability
   routes, status truth, local-link closure, and privacy patterns;
4. scans actual agents, the sole controller, and iMessage source/privacy/log
   surfaces without importing live transport state;
5. compiles package, tests, tools, controller, and agents;
6. runs the stdlib `unittest` suite;
7. checks the exact Pages deploy tree, accessibility structure, internal links,
   project paths, privacy/browser exclusions, release truth, and pinned workflows;
8. verifies census, capability/system evidence, lock, provenance, catalogs,
   controller closure, context closure, and repository privacy.

It installs nothing and needs no network.

## Targeted gates

```sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/context-check.sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/pages-check.sh
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m unittest tests.test_context -v
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m unittest tests.runtime -v
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m unittest tests.controller -v
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m unittest tests.agents -v
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m unittest discover \
  --start-directory tests/imessage --top-level-directory . -v
PYTHONPATH=src /opt/homebrew/bin/python3.11 \
  -m rapp_stack_cubby.imessage.source_scan --root .
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby verify --root .
```

## Interpreting success

A pass proves checked-in local consistency, pinned iMessage metadata and
installer rules, and mocked bridge behavior. It does not prove downloaded
code-signature validity on another host, private owner enrollment, a live
message, live Pages, host attestation, publication, or release conformance.
Those remain blocked in
`../../STACK_LOCK.json` and `../canon/GAP_REGISTER.md`.

On failure, fix the underlying source or status mismatch. Do not delete a test,
weaken a schema, remove an index entry, or overwrite a hash merely to make the
gate green.

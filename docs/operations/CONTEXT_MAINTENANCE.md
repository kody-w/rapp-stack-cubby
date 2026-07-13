# Context maintenance

## What is generated

`CONTEXT_INDEX.json`, `SYSTEM_GRAPH.json`, eight census shard ledgers,
`AUDIT_MANIFEST.json`, the local agent catalog, implementation matrix,
controller catalog, and six `docs/api/v1/` documents are deterministic
generated indexes. The marked facts block in `docs/index.html` is generated.
Canonical profiles, ADRs, operations, schemas, and all other HTML/CSS are
reviewed source.

## Update procedure

1. Change tested implementation and its focused tests.
2. Update the relevant canonical profile and `IMPLEMENTATION_STATUS.md`.
3. Update `GAP_REGISTER.md`/`ROADMAP.md` if ownership or sequencing changed.
4. Add or revise a schema when a machine contract changed.
5. Add an ADR for a lasting compatibility, trust, or authority decision.
6. Update the inventory maps in `src/rapp_stack_cubby/context.py` for a new
   load-bearing artifact.
7. Regenerate:

   ```sh
   PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.audit --root .
   PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.graph --root .
   PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.context --root . --write
   PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.catalog --root . --write
   PYTHON=/opt/homebrew/bin/python3.11 scripts/pages-build.sh
   ```

8. Review the generated diff. Update checked `original_new` and
   `generated_local` hashes in `PROVENANCE.json` and `STACK_LOCK.json` only
   after verifying the bytes and claims.
9. Run:

   ```sh
   PYTHON=/opt/homebrew/bin/python3.11 scripts/context-check.sh
   PYTHON=/opt/homebrew/bin/python3.11 scripts/pages-check.sh
   PYTHON=/opt/homebrew/bin/python3.11 scripts/check.sh
   ```

## Rules

- Keep entry IDs stable; add aliases only through a deliberate schema version.
- Keep entries and capability routes sorted.
- Run `refresh-census` only with authenticated `gh`, an exact UTC RFC3339
  cutoff, and an explicit repository-local candidate path. It never promotes.
  Directly inspect/classify every new or changed relevant repository before
  updating `SOURCE_CENSUS.json`; preserve old `evidence_head_sha`. Treat the
  existence cutoff and bounded observation window separately, retain actual
  inventory/head request timing and response digests, and never stamp all
  heads with one cutoff.
- The raw public snapshot, graph overlay, shards, and audit manifest must make
  external crawl reports unnecessary. Every promoted API/head field must
  cross-bind to its local raw record, and every shard must embed the complete
  promoted records. Current movement after a closed window is separate drift,
  never a retroactive edit of an earlier inspection.
- Every path must be repository-relative, contained, and present.
- Dependencies must remain acyclic; bootstrap prerequisites appear earlier.
- Every selected capability routes to tested implementation or named future
  owner. Every implementation-matrix future owner has an indexed todo.
- Essential context contains only local links. Put external evidence URLs in
  provenance/census artifacts, not required reading.
- Never downgrade current/future truth because a schema or external demo
  exists.

When the index schema changes incompatibly, create a new version, update the
validator first, regenerate, and retain migration notes in an ADR.

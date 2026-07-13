# RAPP end-to-end handoff

## What RAPP is

RAPP is a local-first agent system: independently discoverable BasicAgent
files are assembled with a soul, loaded by a brainstem, exposed through one
loopback chat wire, and supervised as isolated child twins. The selected end
state adds deterministic artifacts, signed replay-safe twin transport, one
owner-only iMessage edge, and exact-commit publication. Historical ecosystem
variants are evidence, not dependencies.

The authenticated public inventory contains exactly **307 repositories** at
the inclusive existence cutoff **2026-07-13T08:57:20.399000Z**. Its bounded,
non-atomic observation window ended at **2026-07-13T09:09:18.274404Z**; every
head retains its own API response time. Its cross-bound raw snapshot, eight
full-record digest-bound shards, and complete twelve-repository drift review
are local, with five later-moving heads separate. This repository was absent
from that public inventory and is the separate complete local product node.

Start with `../../AI_CONTEXT.md`, then
`../canon/SYSTEM_MODEL.md`, `../canon/IMPLEMENTATION_STATUS.md`, and
`../canon/GAP_REGISTER.md`.

For a fresh Mac or fork, use
[`IMESSAGE_ONBOARDING.md`](IMESSAGE_ONBOARDING.md) as the complete
owner-only bridge tutorial.

For a fresh developer, the dependency order is exact:

1. `DEVELOPER_SETUP.md`: select explicit external roots, fetch locked inert
   bytes separately, and run `scripts/bootstrap-development.sh`;
2. run `rapp-stack-cubby doctor` in offline mode;
3. run `scripts/demo-product.sh` with `--cleanup` and retain only its
   content-free local receipt;
4. read `ISOLATED_HATCH.md` and `LOCAL_LIFECYCLE.md`;
5. use `PROVIDER_AUTH.md` and opt into token-file-backed `models`,
   `provider-preflight`, and `provider-smoke` only for a real live child;
6. use `IMESSAGE_ONBOARDING.md` only after a public unchanged candidate exists;
7. use `PACKAGING_AND_RELEASE.md`, `EXACT_COMMIT_PROMOTION.md`, and the root
   checklist for promotion.

## Where every capability lives

| Capability | Location | State |
|---|---|---|
| BasicAgent, registry, provider/auth, storage, tool loop, HTTP | `../../src/rapp_stack_cubby/runtime/` | implemented, including explicit private token file/device login and this-host live provider proof |
| Twelve focused actual agents | twin `agents/` and generated agent catalog | implemented |
| Soul/rapplication source | twin `soul.md` and rapplication directory | implemented source |
| Sole streamable controller | top-level cubby `agents/rapp_stack_cubby_agent.py` | implemented recoverable lifecycle and verified-install adoption |
| Controller loadout and `/chat` route | controller support plus runtime/CLI | implemented authenticated deterministic controller-only bootstrap; loadout remains secret-free |
| Capability ownership | implementation matrix and `../../CONTEXT_INDEX.json` | generated truth |
| Census/evidence refresh | candidate-only authenticated refresher, raw snapshot, shard/audit/graph generators | implemented; promotion requires direct review |
| Current source/privacy scan | source manifest, packaging scanner, Pages checker, focused Security helper | implemented for current local trees/outputs only |
| Full publication scanner | canonical branch/tag/configured-remote history, nested release assets, exact Pages, public redownload, supplied Actions logs | implemented locally; candidate/final signed executions await explicit public inputs and next workflow wiring |
| Artifact chain | packaging package, source/rapplication/egg manifests, indexes, schemas, and packaging tests | implemented local development and offline installed-byte attestation |
| Twin trust | protocols, controller/runtime, transport schemas and runbook | implemented local profile |
| iMessage | bridge package, pinned installer, config/status schemas, onboarding runbook, and tests | implemented source and in-process authenticated route proof; live enrollment/public twin pending |
| Static Pages handoff | site/API generator, checker, tests, pinned workflow, Pages runbook | implemented locally; live deployment pending |
| Publication | promotion runbook, checklist, release workflow | prepared; exact public proof pending |
| Neighborhood/fleet/cloud | matching canonical profiles | mapped/reference only |

The exact capability-level route is machine-readable in
`../../CONTEXT_INDEX.json`; no external index is needed.

## Run and test

```sh
export PYTHONPATH=src
/opt/homebrew/bin/python3.11 -m rapp_stack_cubby context --root .
PYTHON=/opt/homebrew/bin/python3.11 scripts/check.sh
```

For a local product proof, follow `DEVELOPER_SETUP.md` and run:

```sh
scripts/demo-product.sh --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER" \
  --receipt "$EXTERNAL_ROOT/demo-receipt.json" \
  --cleanup
```

The demo uses the real registry/orchestrator/tool loop, authenticated global
controller `/chat`, signed twin-chat, installed source/venv, and the explicit
network-free attestation provider. It never publishes, enrolls, or sends.

## Hatch

Use `DEPENDENCY_FETCH_AND_VENDOR.md`, `PACKAGING_AND_RELEASE.md`, and
`ISOLATED_HATCH.md` for the complete offline artifact route. The egg hatcher
verifies every byte before extraction, installs only bundled dependencies,
writes product/private-instance identities in the installed manifest/receipt,
promotes atomically, and does not start.
Use `CONTROLLER_LOADOUT.md` and `LOCAL_LIFECYCLE.md` for the separate
exact-repository controller lifecycle. Production controller hatch verifies
requested exact HEAD separately from the self-excluding source manifest.
The production path is signed build, `verify-release`, digest-bound hatch,
static `verify-install`, authenticated `controller adopt`, then start the
returned private instance RAPPID using the installed venv/source and an
explicit child model. The global controller route itself is deterministic,
model-free, and bearer-authenticated. Operate it only with the exact
`rapp-stack-cubby controller` commands in `LOCAL_LIFECYCLE.md`.
Start, health, signed chat/self-test, key rotation, stop, archive, and purge
use private state, phase journals, and idempotency keys. The public product
RAPPID is never a running child identity.

## Release phases and what remains

- **A — source candidate:** one clean commit, CI/local checks, signed
  deterministic candidate build, and offline installed-byte demo.
- **B — protected prerelease:** unchanged commit/tag/assets, public
  redownload, GitHub attestation, and byte equality.
- **C — live private enrollment:** this host's content-free provider
  catalog/preflight/tool-loop proof exists; owner-only account auto-discovery,
  FDA/Automation, and one private message proof against the exact public
  commit remain.
- **D — released Pages/promotion:** deploy only the verified public artifact
  for that same commit, record final content-free evidence, and promote without
  a source commit or rebuild.

`../canon/GAP_REGISTER.md` is complete and owner-routed:

1. protected public prerelease/redownload attestation;
2. exact-public-product live provider plus iMessage private owner proof (the
   current host provider gate alone is implemented);
3. released Pages deployment/final same-commit promotion;
4. a fail-closed full publication scanner over history, releases/nested
   archives, deployed Pages, and Actions artifacts/logs.

Packaging trust is resolved locally. `../../STACK_LOCK.json` intentionally
remains build-blocked on the final source commit, public/GitHub attestation,
download parity, live Pages, and live owner proof.

## Improve safely

Change tested code and focused tests first. Update canonical status and gaps,
schemas, and a lasting ADR where required. Regenerate indexes rather than
editing them. Keep one wire, actual-agent identity, controller/child isolation,
exact source identity, no dynamic code, and the default-deny privacy boundary.
Run context and full checks. Follow `CONTEXT_MAINTENANCE.md`.

Do not fetch an external repository to fill an apparent conceptual gap. If a
local profile is incomplete, improve this repository and its tests; retain any
new external locator only as provenance evidence.

## Publish

Publication does not exist yet. The local deterministic artifact chain and
static Pages handoff are implemented; execute the remaining release gates in
`PACKAGING_AND_RELEASE.md`: final exact commit/signing, messaging proof, full
scanner matrix, supported-host attestation, staged/public byte comparison, and
sanitized receipt. A green development build or Pages preview is not a release.

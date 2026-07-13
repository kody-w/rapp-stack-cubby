# Account crawl

## Refreshed public snapshot

The public `kody-w` account inventory uses the inclusive repository-existence
cutoff **2026-07-13T08:57:20.399000Z**. That cutoff is deliberately distinct
from the observation window:

| Event | Actual UTC time |
|---|---|
| capture started | `2026-07-13T09:07:31.710577Z` |
| inventory completed | `2026-07-13T09:07:34.591993Z` |
| head queries started | `2026-07-13T09:07:34.592407Z` |
| capture completed | `2026-07-13T09:09:18.274404Z` |

This is a bounded, **non-atomic** observation window, not an assertion about
one historical instant. Repositories with `created_at` on or before the
existence cutoff are eligible for inventory. Each default-branch head applies
only at its own `current_observed_at`, taken from that head query's actual
response timing; the 307 heads do not share a fabricated cutoff timestamp.

Authenticated `gh` 2.88.1 used GitHub REST API version `2022-11-28`, explicit
`page`/`per_page=100` pagination, and the owner/full-name ascending query.
Four pages returned **307 unique public repositories**. Every page retains its
request/response time, duration, ETag, safe response headers, and canonical
body digest. Every repository retains a separate inventory record and head
response record with timing, endpoint, response digest, status, and safe
headers. `public-account-snapshot.json` indexes eight canonical
`docs/research/raw/shard-*.json` files so all evidence remains local without
creating one oversized Pages file.

The canonical compact-JSON SHA-256 values are:

- combined ordered repository/head records:
  `b714ecc753e8f3545c43697a9d430837fed54752edd040c65eb6d267541cceae`;
- inventory records:
  `ede143debd6a87f1cd6daee5186cdec01eeb9cfc5cda7a2fca84b4e8aaccd718`;
- head observations:
  `ceab5a6ee61fb3127f3e81808b35c5b5e8c571077ad52e8e9d465bdb2e4bd021`.

Exact heads resolved for 302 repositories. Actual commit-list queries returned
the empty state for `BigNerdRanch`, `copilotsdktown`, `inventwithpython`,
`LPTHW`, and `Treehouse`.

The refresh used direct GitHub API and repository bytes. `rapp-spine`,
`rapp-map`, `rapp-god`, `RAPP-Bible`, the grail, and other indexes were not
authority for another repository.

## Antecedent audit and cutoff semantics

The prior direct evidence release covered 299 repositories on 2026-07-12.
Its notes and line locators remain pinned to each record's
`evidence_head_sha`. The refresh adds `current_head_sha` and `head_drift`;
it does not move old citations to new bytes. Twelve relevant antecedent heads
changed and every one now has a complete exact-new-head review. Of the eight
repositories originally inspected as new, three still match that inspection
head and five have explicit `post_window_drift`; 282 other heads are unchanged
and five remain empty.

The cutoff bounds repository existence, not head history. A later publication,
rename, push, deletion, or new repository requires another candidate refresh.
Movement after an inspection is recorded separately and never mixed back into
that inspection or given its old line evidence.

`rapp-stack-cubby` did not exist in the antecedent or refreshed public account
inventory. It is the explicit local product node
`product:local/rapp-stack-cubby`, not a fabricated public audited antecedent,
and is excluded from the 307-repository count.

## Snapshot difference

Compared with the 299-record antecedent snapshot:

- **Added (8):** `rapp-heir`, `rapp-play-pokemon`, `rappterverse-data`,
  `static-dynamics-365`, `static-oracle-fusion`, `static-sap-s4hana`,
  `static-servicenow`, and `static-zuora`.
- **Removed:** none.
- **Renamed:** none.

Current classification totals are **C=39, I=76, A=84, L=20, U=88**.
Case-insensitive name sorting and `sorted_index % 8` produce shard coverage
**[39, 39, 39, 38, 38, 38, 38, 38]**.

## Required drift-review closure

All twelve required antecedent C/I or directly load-bearing changes were
inspected at the exact newly observed head. `AUDIT_MANIFEST.json` and the
assigned shard retain the recursive-tree locator/count, evidence-to-current
comparison, README, spec/manifest, relevant implementation, root-license and
Pages paths/state, disposition, and capability-change finding.

| Repository | Exact reviewed head | Disposition / capability change |
|---|---|---|
| `localFirstTools` | `42c48ca7f5578b724c7d13a1128c5c4d5c236733` | Retain A; only generated HN/health evidence moved. |
| `localFirstTools-main` | `de492efcd12cfeeda3c35b1de1be86a15ce868db` | Retain A; automation state/feed movement only. |
| `localtoolsdev` | `cf116bb203ddf9636d3dceed253637182e260d58` | Retain A; generated HN/health evidence only. |
| `mars-barn-opus` | `bfe158952cbeb13568cdf69013a6a7456c30f837` | Retain I; adds deterministic mission-readiness cohort/cascade analysis and reports. |
| `mars-chain-node` | `1b85b42349963693c322e83d751ad39c939e6b6e` | Retain A; consensus data advanced, protocol unchanged. |
| `rapp-moonshots` | `789f9334050c40d115216d37f20f9b77e8429d12` | Retain A; notable 42-commit/104-file drift adds tested Adaptive Orb voice/gaze/gesture PWA evidence. |
| `rappter-plays-pokemon` | `25e60c3bb1b665a6fcd654277a1ea0dfdd65d254` | Retain A; adds bounded Rock Tunnel route guidance and tests. |
| `rappterbook` | `d1f0c0d2bb8cb41df5632594a7111d2f0269fd49` | Retain C; notable 51-commit drift is dominated by 299 generated Pages/API/data files; core contracts were rechecked. |
| `rappterbook-agent-exchange` | `75a61c43ea33d563dc00a9f249929fa8aef29aff` | Retain A; deterministic simulation/rendered state only. |
| `rappterbook-first-bond` | `6da27b309760f2b2c0b97dae0a1ad15a906c4fd3` | Retain I; frame-4 prototype adds bounded bond state/feed and human icon-study gates. |
| `rappterverse` | `87da5bd529aa89ec8ef1cba719bdd86dcdaa77f1` | Retain I; broad replay/state/workflow/PII hardening, no local selection change. |
| `RAR` | `c1b12083a0183d459b0ed711c06a666213e6ccdd` | Retain C; only Rappterpedia Dream Catcher stream frames moved. |

The audit is complete. None of these findings silently promotes external code
into this product or changes a selected local capability.

## Separate post-window drift

The following newly inspected repositories later moved and are recorded
separately, without pretending their earlier inspection covered the new bytes:
`rapp-play-pokemon`, `rappterverse-data`, `static-oracle-fusion`,
`static-sap-s4hana`, and `static-servicenow`. Their current observation and
prior evidence heads are both explicit in the census/shards. They are not
retroactively mixed into the eight new-repository inspection records.

## New-repository direct inspection

Every added repository was inspected through its exact recursive tree,
README, specification/manifest and code where present, root license, and
GitHub Pages state. Full category records and locators are in
`AUDIT_MANIFEST.json` and the generated shards.

| Repository | Exact evidence head | Class | Direct finding |
|---|---|---:|---|
| `rapp-heir` | `58362a43bbf02d3909aacb6617b745f0fca8d0ad` | I | 72-file local-first signed Circle/quest PWA with protocol, verified BasicAgent manifest, tests, MIT license, and live workflow Pages. |
| `rapp-play-pokemon` | `27bdbc5a2c76920f1e6745f578a928ca4625a2b3` | I | 22-file canonical RAPP cartridge with a ROM-free boundary, BasicAgent manifest/code, tests, CI, and MIT license; no Pages. |
| `rappterverse-data` | `7bc0d2911d231de4e2bb04a425b6a2b8a86e8263` | I | 178-file deterministic synthetic-data/world-pack implementation with schemas, generators, deny-by-default policy, scanners, split Apache-2.0/CC-BY-4.0 licensing, tests, and live Pages. |
| `static-dynamics-365` | `e784b329613b5f23c7fdcb41956c57ca5208259f` | A | 78-file independently authored public-docs-subset simulator with manifest, deterministic fixtures, injected twin runtime, tests, MIT license, and live Pages. |
| `static-oracle-fusion` | `147f25a05b1c37ab8a3f9b5c060a8a58dcecfe86` | A | Two-file MIT declaration only; no manifest, code, tests, workflow, or Pages. |
| `static-sap-s4hana` | `ad5c130a290f6b9011a1ec7ad4eb1bc0093fdbcc` | A | Two-file MIT declaration only; no manifest, code, tests, workflow, or Pages. |
| `static-servicenow` | `22bb877254036a62b59b36359b32903cd33bc344` | A | Two-file MIT declaration only; no manifest, code, tests, workflow, or Pages. |
| `static-zuora` | `fbc770494e98222cdf7bbc14bec04fd3ec4008a2` | A | Two-file MIT declaration only; no manifest, code, tests, workflow, or Pages. |

## Local evidence closure

`docs/research/shards/shard-0.json` through `shard-7.json` contain all 307
complete promoted records with canonical per-record digests, direct notes,
locators, evidence head, individually timed current head, drift, and applicable
inspection ledger.
`AUDIT_MANIFEST.json` binds each shard's byte digest/count, the raw inventory,
existence cutoff, observation window, methodology, coverage, empty
repositories, twelve drift reviews, and eight new-repository inspection
records. The validator compares every promoted ID/name/URL/visibility/private/
fork/default-branch/description/language/Pages/license/topics/timestamp/head
field with the local raw inventory/head records. `SOURCE_CENSUS.json` is the
human-reviewed census source. No external crawler report or workstation path
is required working context.

Owner authorization covers owner-original code only. It does not clear forks,
third-party, generated, copied, vendored, data, font, or asset bytes.
Repository labels are not a substitute for per-file provenance and license
review.

## Preserved synthesis findings

The original cross-repository synthesis remains in `RAPP_END_TO_END.md`.
Important direct findings remain: incompatible RAPPID/cubby/Moment/egg/static
MCP families; pointer/index names that do not confer authority; useful but
incompatible runtime, hatching, messaging, neighborhood, fleet, and cloud
implementations; unsafe broad-bind/import/install paths; shared-origin Pages
privacy hazards; and uneven licensing/provenance. The eight canonical flows
and all named collisions remain preserved there and in `SYSTEM_GRAPH.json`.

## Validation

- 307 sorted census names exactly equal 307 sorted raw inventory names.
- Every promoted API/head field equals its raw record; metadata/head tamper
  tests remain fail-closed even if an attacker recomputes raw digests.
- Every shard equals `sorted_index % 8`; all shard digests validate.
- Every shard covers the exact complete promoted records, not a names-only
  projection.
- All old locators have an explicit evidence head and separate drift.
- All eight added repositories have exact-head category inspection records.
- All twelve required antecedent drift repositories have complete exact-head
  reviews; five later-moving heads remain separate.
- The explicit local product node is not counted as an antecedent repository.
- The inventory and shards contain no credential or machine-local path.

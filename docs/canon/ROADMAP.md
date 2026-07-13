# End-to-end roadmap

The roadmap is dependency ordered, not date promised.

1. **Maintain context and tested local core.** Keep runtime, agents,
   recoverable controller/adoption lifecycle, deterministic controller `/chat`
   route, explicit provider auth/exact-model preflight, product/private-instance
   identity, catalogs, schemas, status, and tests synchronized.
2. **Maintain source and packaging.** Keep the implemented self-excluding
   source manifest, deterministic Store/egg builders, offline dependencies,
   strict hatch, installed verifier, and build→hatch→verify→adopt→start journey
   reproducible.
3. **Maintain signed twin-chat.** Keep the pinned P-256 stack, pairings,
   replay recovery, synthetic vectors, and source/privacy scans green.
4. **Attest owner iMessage.** Maintain the implemented pinned read-only owner
   ingress, durable outbox, recovery, echo suppression, and negative vectors;
   after public release, perform private enrollment and supported-host proof.
5. **Close publication.** Maintain the implemented static Pages and release
   preparation; then scan live surfaces, attest the host, bind exact commit,
   publish, download, and verify.
6. **Only then consider expansion.** Neighborhood, fleet, cloud, groups,
   attachments, or other hosts require separate decisions and trust profiles.

Each phase leaves `STACK_LOCK.json.build_blocked` true until its real evidence
exists. No phase may substitute external repository state for a local
contract, test, or artifact.

## Status distinctions

| Class | State |
|---|---|
| **Profile requirement** | Complete phases 1–5 for the selected v1 claim. |
| **Implemented now** | Phases 1–3 locally, including this-host provider tool-loop proof; iMessage bridge source in phase 4; and the static/preparation portion of phase 5. |
| **Mapped/reference only** | Phase 6 integrations. |
| **Unsafe/deprecated** | Parallelizing across unresolved trust boundaries, publishing demos as releases, or filling hashes speculatively. |
| **Future owner** | Final release/host/public proof is `release-attestation`. Phase 4 live proof and live Pages/publication belong to the release operator. |

Acceptance detail lives in `GAP_REGISTER.md` and
`../operations/PACKAGING_AND_RELEASE.md`.

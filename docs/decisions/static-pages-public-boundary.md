# ADR: static Pages is a public handoff, not a product runtime

## Status

Accepted for candidate `0.1.0rc6`.

## Decision

GitHub Pages publishes only the reviewed `docs/` tree. The front door is
dependency-free semantic HTML and CSS plus deterministic JSON under
`docs/api/v1/`. It has no hosted backend, data-entry form, analytics,
third-party executable resource, browser persistence, service worker, source
map, or request to local/private endpoints.

Core product understanding works without scripting. Source metrics and API
records are generated from the census, capability and implementation matrices,
agent/controller catalogs, context index, system graph, prompt profile, and
explicit release status. The generator updates the API files, every marked
release-state block in `docs/index.html`, and the exact
`docs/pages-manifest.json` inventory.

Committed source always says release pending. A later Pages deployment may
show released downloads only after local `verify-release` validates an
external manifest digest, detached signature, pinned `RELEASE_TRUST.json`,
canonical checksums, every downloaded asset, exact source HEAD/tree/digest,
and GitHub attestations. Pages never embeds artifact hashes; it links to the
release-side checksum asset. Once a release exists, automatic `main` pushes
preserve the released deployment and require an explicit trusted dispatch.

## Consequences

- `scripts/pages-check.sh` scans the exact deploy root and fails closed.
- The 404 surface uses `/rapp-stack-cubby/`-absolute project paths so nested
  missing routes resolve correctly.
- A passing static check proves the local handoff surface, not publication.
- Public release, downloaded-byte equality, live owner enrollment, and host
  attestation remain external gates.

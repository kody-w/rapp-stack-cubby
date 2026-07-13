# Cloud and enterprise profile

## Mapped progression

The mapped progression moves a passing local rapplication to a pinned cloud
function, then to approved Dataverse records and managed Copilot/Teams/M365
surfaces. Only portable public application inputs may cross the boundary.
Local identity mappings, memory, conversations, journals, credentials, and
pairings remain private and require an explicit migration design.

A safe future path needs immutable code, managed authentication,
least-privilege service identity, deterministic record encoding, checksummed
solutions, tenant-scoped authorization, rollback, and the same contract
vectors used locally. A caller-provided GUID is data, not authentication.
Code loaded from mutable storage is prohibited.

## Status distinctions

| Class | State |
|---|---|
| **Profile requirement** | Keep local contracts portable without claiming cloud identity, storage, or deployment conformance. |
| **Implemented now** | Local filesystem storage and provider boundary only; no cloud release path. |
| **Mapped/reference only** | Azure Functions/storage, Dataverse, Power Platform, Copilot Studio, Teams, and Microsoft 365. |
| **Unsafe/deprecated** | Mutable cloud code, caller-supplied memory identity, exported private state, broad service principals, and unpinned one-click deploy. |
| **Future owner** | None in v1; requires a new profile, provenance review, privacy model, and release gates. |

See `SYSTEM_MODEL.md`, `SECURITY_AND_RELEASE.md`, and
`../operations/PACKAGING_AND_RELEASE.md`.

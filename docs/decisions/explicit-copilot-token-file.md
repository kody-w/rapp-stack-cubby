# Explicit Copilot token file

## Decision

Live provider authentication uses either an explicit process
`GITHUB_TOKEN`, an explicitly selected private token file, or a final `gh auth
token` attempt. No private path is discovered implicitly. The preferred
product flow is the bounded GitHub device flow exposed by `provider-login`.

The token file is versioned bounded JSON, absolute, regular, mode 0600, and
free of symbolic-link components. A controller passes only that external path
in fixed child argv; it never copies the path or credential into workspace
state, logs, receipts, Pages, or artifacts. Exact live model selection is
verified against the current chat-capable catalog and never falls back.

## Consequences

Copilot CLI and this runtime have separate authentication selection.
`copilot login` does not satisfy the runtime contract automatically. A `gho_`
credential that fails Copilot exchange produces content-free remediation
rather than a generic transport error. Existing compatible private JSON may
be selected explicitly, while packaging and publication remain
credential-free.

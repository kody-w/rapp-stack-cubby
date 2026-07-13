# RAPP stack rapplication source

This is the reviewed source descriptor for the agent-first
`rapp-application/1.0`. It includes twelve actual child agents, their soul and
catalogs, a byte-identical controller singleton, and a dependency-free local
handoff UI. The build command stages the complete repository product beneath
`source/` and injects only the four verified archives from
`DEPENDENCY_LOCK.json`.

`manifest.json` and `index_entry.json` describe source intent. They do not
claim a release or final commit. Generated Store and egg manifests in `dist/`
bind the explicit build revision and exact source-tree digest.

Only the singleton controller is streamable. Internal `*_agent.py` files stay
actual agents. Signed twin-chat and owner-only iMessage source are included,
but keys, enrollment, messages, journals, and runtime state are never bundled.
The static UI performs no requests and stores no browser data.

# Tools

`build_controller_loadout.py` invokes the deterministic controller-only
loadout builder. It requires an explicit absolute external output directory,
copies only the source-hash-verified controller, writes a private
`rapp-controller-loadout/1.0` manifest, and never mutates a source worktree or
`.brainstem`.

The deterministic package/egg chain and static Pages build/check tools are
implemented locally. Live publication, final signing/attestation, and public
postflight remain pending.

# Clean global RAPP controller runtime

This loadout contains only `RappStackCubbyController`.

`RAPP_CONTROLLER_ROUTE/1.0` is a reserved runtime route enabled only by the
explicit controller-route configuration. The runtime validates its canonical
JSON envelope, executes the named controller through the normal registry/tool
path exactly once, and returns a SHA-256 result proof without model selection.
The soul never interprets, infers, or rewrites controller actions.

All non-reserved `/chat` requests retain the normal isolated runtime behavior.
Paths, keys, private instance identifiers, message content, and raw controller
results must not enter operational logs.

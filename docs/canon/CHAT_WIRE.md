# Chat wire profile

## Sole capability endpoint

The only capability endpoint is loopback `POST /chat`; `GET /health` is
operational only. All other paths/methods fail closed. The server enforces
loopback binding, Host checks, exact JSON content type, fixed body length,
request bounds, and no transfer encoding.

The separately configured global controller runtime accepts only a canonical
deterministic controller envelope through authenticated local control chat:

```json
{"user_input":"synthetic RAPP_CONTROLLER_ROUTE/1.0 envelope"}
```

An auth-enabled runtime requires one exact `Authorization: Bearer <base64url>`
header backed by an explicit mode-0600 32-byte token file. Before disclosing a
bearer or request body, the iMessage bridge verifies the server's HMAC response
to a fresh content-free `/health` challenge. Missing, duplicated, oversized,
malformed, or wrong authorization is rejected before route/provider/tool
execution. The token is never returned or logged.

The response contains the canonical controller result separately from the
exact child response. `rapp-controller-result-proof/1.0` binds the route
request SHA-256, canonical controller-result SHA-256, exact response SHA-256,
verified signed-twin status, instance RAPPID, key epoch, and terminal status.
For successful chat, the returned response bytes equal
`controller_result.child.response`. A completion log marker is compatibility
metadata, not proof. A signed terminal rejection is explicit and never treated
as normal chat output.

## Signed controller use of the same route

Controller `chat` and `self_test` never send plaintext to the child. They
serialize a signed Commons/twin envelope into the sole outer field:

```json
{"user_input":"synthetic canonical signed rapp-commons-event/1.0 JSON"}
```

Controller-launched and adopted children run with explicit `signed_only`
configuration. Ordinary text and unrelated JSON sent directly to a child
port are rejected before provider or tools. Signed wire strings must already
be the exact canonical UTF-8 bytes; parsing and reserialization do not repair
noncanonical input.

After verification and replay claim, the orchestrator converts only the
signed inner payload to the ordinary internal request and runs the same agent
loop. It serializes the signed child response into the normal outer
`response` field. Outer session/log/model fields remain bounded compatibility
metadata and are not trusted by the controller.

Decoded or textual objects claiming a twin request, Commons wrapper, or signed
response schema fail closed before model execution when escaped, duplicated,
malformed, over-depth, or noncanonical. On the plain global runtime only, JSON
with no recognized twin claim remains ordinary user text.
There is no `/api/agent`, hidden route, relay endpoint, or direct agent-call
fallback.

Machine contracts are in the brainstem and twin-chat schemas.

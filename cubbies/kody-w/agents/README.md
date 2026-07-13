# Controller location

`rapp_stack_cubby_agent.py` is the one top-level streamable controller. It is
a genuine single-file BasicAgent implementation; lifecycle behavior is not
hidden in package imports.

The controller has a guarded, non-release development hatch for exact verified
source trees. Production hatch requires the future release source manifest.
Internal `*_agent.py` files remain actual, independently discoverable agents
inside each child and are never flattened into controller tools. Signed
twin-chat, pairing, replay, and rotation are implemented through the sole
child `/chat`; iMessage, package/export construction, Pages, and publication
are still future work.

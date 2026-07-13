# Test fixtures

Committed fixtures must be unmistakably synthetic, deterministic, and free of
real identities, messages, credentials, keys, local paths, and runtime state.
Current tests generate temporary contract copies inside the repository and
remove them after each test; no data is read from the user's home directory.
# Synthetic fixtures

Every fixture in this directory is synthetic and test-only. The twin-chat
vector contains public JWKs and signed example messages only; it has no
production identity, private key, credential, user message, or runtime state.
It fixes key epoch 7 and canonical low-S P1363 signatures for high-S rejection
and cross-implementation verification tests.

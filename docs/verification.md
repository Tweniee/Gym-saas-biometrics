# Verification

Automated checks run locally on macOS with Python 3.13, Node/ts-node, isolated MongoDB replica-set tests and headless Chrome. Real R2 and email are not used.

- Connector: durable replay, mismatched acknowledgement, disk full, token refresh/rotation boundaries, command leases, identity checks and simulator behavior.
- ZK TCP emulator: fragmented packets, serial/size/user/attendance reads, 8/16/40-byte records, local time/DST rejection, snapshot reorder/restart deduplication, lost acknowledgements, unsupported layouts and shared process locks.
- Backend: strict ownership DTOs, connector-vs-human token separation, role/module wiring, single-use pairing, cross-gym isolation, local registration idempotency, revocation, attendance projection and release failure/retry/immutability with mocked private storage.
- Browser: separate owner/super-admin routes, functioning setup actions, expiring codes, cancellation on gym change, backend blob download, independent heartbeat/device freshness, scoped member mapping and failed-poll recovery.
- Legacy reader behavior remains covered separately.

See [recorded check results](verification-results.md) and [commands and manual acceptance flow](setup-and-testing.md).

Windows installer compilation/lifecycle, actual DPAPI/ACL handoff, physical hardware compatibility, signing and a live backend-mediated R2 upload/download remain unverified. Do not treat emulator success as hardware certification.

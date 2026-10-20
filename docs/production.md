# Production boundaries

The connector supports a read-only ZK-compatible TCP adapter for compatible Identix-class devices. Protocol-emulator tests cover serial/data handshake, 8/16/40-byte attendance records, UID mapping, timestamp conversion, known IN/OUT interpretation, replay/deduplication, unrelated services and bounded I/O. No physical model/firmware has been certified in this session.

Before a gym pilot:

1. Test the exact device model/firmware on Ethernet, including its communication key, serial stability, user IDs, record layout and selected scan interpretation.
2. Verify device wall time/timezone. Ambiguous/nonexistent DST timestamps are rejected; no clock correction or silent fold guess occurs.
3. Validate Windows installation, UAC, SYSTEM/Administrators ACL, machine DPAPI sharing, service startup, reboot, failure restart, upgrade, rollback and uninstall.
4. Sign the setup/service executables and installer, verify signatures, measure resource usage, then upload the installer through the super-admin page. Only backend StorageService accesses R2. PE structure/SHA-256 checks do not verify a publisher signature.
5. Run the backend index migration against a Mongo replica set before enabling pairing/ingestion/release publication.
6. Choose raw-event/audit retention and operational monitoring. There is no automatic support email or external ticket.

The ZK adapter does not write users, fingerprints, enrollment, device clock, door permissions or expiry settings. The generic access API remains available for separately validated adapters; simulator access is not hardware enforcement. Automatic membership cancellation hooks across all member workflows are outside this change.

Snapshot log protocols do not expose a universally stable event sequence. Event identity uses semantic record fields and an occurrence ordinal within the serial-bound generation. Acknowledged identities survive restart; unknown records remain unresolved. Detected log shrinkage reports a persistent data gap. Deleted logs cannot be recovered, and identical scans reused after a reset cannot always be distinguished from prior records. Preserve device logs and validate the device's retention behavior.

There is no automatic updater. Installer upgrades preserve protected local state. Revocation rejects new protected cloud requests; an already-running read/upload cannot be recalled. A native macOS app/DMG, login Keychain store and opt-in per-user LaunchAgent are implemented; real Keychain consent, login/reboot persistence, upgrades, sleep recovery and physical hardware remain Mac pilot checks. See [macOS packaging](../packaging/macos/README.md). The admin release uploader supports independent Windows, Apple Silicon and Intel releases; all private storage goes through the backend.

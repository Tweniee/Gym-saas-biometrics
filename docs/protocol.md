# Protocol, identity and recovery

The service requires cloud connectivity for normal device work. No inbound LAN/cloud listener or port forwarding is used. The setup utility writes credentials locally; Angular never receives installation credentials.

## State and credentials

The production state directory is `%ProgramData%\Zenvore\BiometricConnector`. Setup runs elevated; the service runs as LocalSystem. The installer grants only SYSTEM and Administrators access to this directory. Both processes use the same machine-DPAPI credential blob. Machine DPAPI alone is not access control: preserve the directory ACL.

`state.sqlite3` uses WAL and `synchronous=FULL`. It contains checkpoints, at most one pending batch per device, confirmed simulator access state, identity pins, durable command receipts and health timestamps. Device passwords and installation credentials are not stored in SQLite. There is no fingerprint-template storage or upload.

New tokens are fetched after restart and 60 seconds before expiry. Replacing the credential file invalidates a cached token. Rotation is requested after 30 days; the old secret remains usable for 24 hours to recover a lost response/save. Concurrent repeated rotation during that grace is rejected. Revocation removes both server-side credential verifiers.

## Attendance

1. Acquire the device lock shared by scheduled and manual operations.
2. Upload existing persisted pending bytes before any new fetch.
3. Read the cloud-acknowledged checkpoint and fetch at most 200 source records.
4. Normalize offset-aware timestamps to UTC, preserving raw timestamp and configured IANA timezone.
5. Persist the batch before starting its upload.
6. Validate the cloud's committed flag, generation, position and exact event-ID acknowledgement.
7. Atomically record acknowledged native identities, update the local checkpoint and delete pending bytes.

The simulator event identity is SHA-256 of compact UTF-8 JSON `[deviceId,generation,nativeRecordIndex]`. Two scans for the same user at the same timestamp retain different source indices. Record indices must be increasing and generation must change when they are reused. Device resets and overwritten retained history produce a persistent data-gap report, not a claim of complete recovery.

If a process crashes after fetch but before persistence, the unchanged cursor allows refetch. After persistence, pending bytes survive restart. After cloud commit but before local acknowledgement, the same batch is replayed idempotently. Server transactions include source events, attendance projection and cloud checkpoint. An inconsistent event identity/payload is rejected rather than silently replacing history. A disk-full failure does not acknowledge data.

A sync cycle processes at most ten pages (2,000 source records) before yielding; additional retained history is fetched in later cycles. A successful command means that bounded operation succeeded; the UI does not claim unlimited history is caught up. Initial import is explicitly limited by the chosen start timestamp, which cannot be more than 31 days before assignment. Normal sync never clears device logs.

## Access

The backend increments a desired state version for each member/device change and supersedes older queued toggles. The connector fetches current desired state before acting, uses observed-state readback before repeating uncertain writes, and never applies a lower version over a locally observed higher version. Device success is confirmed separately from cloud save.

Reconciliation reads current desired states every scheduled cycle, including after restart/outage, so an expired historical command does not prevent convergence. Attendance can continue independently of access capability. The simulator models configuration writes/readback; it is not a door controller, enrollment engine or emergency-exit mechanism. Automatic hooks from every membership lifecycle transition and real device expiry enforcement require separately validated product/device integration.

## Bounds and retention

- 16 devices per gym; one assigned connector per device.
- One 200-event pending batch per device, maximum 1 MiB per serialized batch and 64 MiB pending payload total.
- SQLite database maximum 65,536 pages (normally 256 MiB), default WAL autocheckpointing.
- Commands: one-day expiry, three attempts, renewable 120-second lease; local receipts retained seven days with a 10,000-row cap.
- Local logs: 1 MiB each, three rotated backups. Only sanitized operation/error metadata is logged.
- Discovery engine: explicitly selected private IPv4 `/24` or smaller, at most 256 hosts, four documented ports, 16 workers, at most one second per handshake, 12-second overall result deadline and 32 returned candidates. Adapter implementations must honor I/O timeouts.
- Simulator fixture: 2 MiB maximum, 16 endpoints; discovery performs no network scan.

Backend command/audit/event/support retention and alert delivery are deployment policies still to configure. The status UI reports missed heartbeats without relying on shutdown notifications. No recurring alert sender is installed, so the same outage cannot trigger repeated notifications from this feature.

## Identix / ZK-compatible TCP

The adapter reuses this repository's TCP protocol behavior without bundling a third-party SDK. It reads serial number, size counters, enrolled user IDs and known attendance records. It never clears device attendance or writes user/access/clock settings. See production.md for the snapshot identity and retention limitations. Naive packed wall time is converted using the assignment timezone; ambiguous/nonexistent DST times fail explicitly.

Ethernet discovery starts after pairing and on active interface/address changes, scans one private network on TCP 4370 (at most the local /24), and requires protocol serial/size responses. The owner selects a candidate and a complete serial/user/attendance read is required before connection readiness. Manual IP/port and communication key are supported. Keys use a separate machine-DPAPI blob under the same restricted directory. Scheduled/manual operations and the setup app coordinate assigned devices through per-device OS file locks.

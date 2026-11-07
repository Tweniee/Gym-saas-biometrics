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
- SQLite database maximum 262,144 pages (normally 1 GiB), shared by all devices (500,000 remembered events of one device take about 125 MiB), default WAL autocheckpointing.
- Commands: one-day expiry, three attempts, renewable 120-second lease; local receipts retained seven days with a 10,000-row cap.
- Local logs: 1 MiB each, three rotated backups. Only sanitized operation/error metadata is logged.
- Discovery engine: explicitly selected private IPv4 `/24` or smaller, at most 256 hosts, four documented ports, 16 workers, at most one second per handshake, 12-second overall result deadline and 32 returned candidates. Adapter implementations must honor I/O timeouts.
- Simulator fixture: 2 MiB maximum, 16 endpoints; discovery performs no network scan.
- Identix/ZK reads: at most 100,000 users, 500,000 attendance records and 32 MiB per transfer. Each socket operation times out after the optional config key `device_timeout_seconds` (default 15, allowed 1-60; separate from `timeout_seconds`, which is only the cloud HTTP timeout); the whole session has a budget scaled to log size (minimum about 50 KiB/s, capped at 600 s; over UDP it adds three operation timeouts of slack once per session for retries). Sessions are cancellable: the TCP connect is one non-blocking attempt polled in one-second slices, socket waits are sliced to one second, and the runtime's stop flag is checked between slices, so a shutdown closes the connection within about a second without waiting for EXIT (EXIT is otherwise sent only after a finished session, with a two-second wait). A cancel is marked locally (`reason` `CANCELLED`, cloud code still `DEVICE_UNREACHABLE`): the runtime then skips rediscovery, the unreachable report and the stored error, and a command cut off by shutdown posts no result, so its lease expires and the cloud leases it again after the restart. Records skipped while decoding (deleted members, invalid times) are counted in the local store only (`zk-skipped:<device>`), shown in the setup app and in `diagnostics`, and never sent to the cloud.

Backend command/audit/event/support retention and alert delivery are deployment policies still to configure. The status UI reports missed heartbeats without relying on shutdown notifications. No recurring alert sender is installed, so the same outage cannot trigger repeated notifications from this feature.

## Identix / ZK-compatible TCP

The adapter reuses this repository's TCP protocol behavior without bundling a third-party SDK. It reads serial number, size counters, enrolled user IDs and known attendance records. It never clears device attendance or writes user/access/clock settings. See production.md for the snapshot identity and retention limitations. Naive packed wall time is converted using the assignment timezone; ambiguous/nonexistent DST times are never guessed; such records are skipped and counted (below).

Packets use the ZK framing with the ones'-complement checksum computed over the packet as sent (including the new reply id), matching captured device traffic and pyzk. Strict firmware drops packets with a bad checksum.

The attendance record count is re-checked if a punch arrives during the read. Individual undecodable records (deleted member in the 8-byte layout, impossible/DST-ambiguous/nonexistent timestamps, bad UTF-8, empty user id) are skipped and counted in the log rather than blocking the device; the read fails with `INVALID_DEVICE_DATA` if most records are undecodable. One device dump is taken per sync run and the snapshot is reused for up to 120 s.

Over UDP a lost datagram costs only the chunk it belonged to, not the whole read: a 16 KiB chunk whose reply times out (each datagram wait is at most five seconds), whose data datagrams are cut short, or whose PREPARE_DATA was lost (the first data datagram arrives where a PREPARE_DATA was expected and is shorter than the chunk) is requested again, three attempts in all, each with a fresh reply id, before the device is reported unreachable. Reply ids strictly increase within a session and are never reused: over UDP the next id follows the last id sent, not the last reply received, so a stale datagram cannot make a retry reuse the id of a failed attempt (TCP derives the next id from the device reply, as pyzk does). After a loss, the first reply to a retry (and to every command after it) is matched by reply id, so a stale reply cannot be mistaken for it. Follow-on datagrams of a transfer are accepted whatever id they carry, because some firmware does not echo it, except that a datagram carrying the reply id of any failed attempt is dropped for the rest of the session (it arrived late, after the queue was drained, possibly during a later chunk). If follow-on data would overflow the chunk, or a data datagram arrives where the trailing ACK belongs, the chunk is requested again instead of failing with `INVALID_DEVICE_DATA`; but if every attempt of a chunk overflows, the firmware consistently sends more than requested, which is a protocol incompatibility and is reported as the non-transient `INVALID_DEVICE_DATA` rather than a transient unreachable device. A chunk that fits one datagram is followed by a short wait for its trailing ACK so that a late ACK cannot shift later replies. A UDP session that never lost a datagram accepts any reply, as pyzk does, for firmware that does not echo the reply id. The size reads must also agree with the dumps: users reported but an empty or wholly unreadable user dump, attendance that maps to none of the users (ten or more records), or an empty attendance dump while the count stays positive after one recount are `INVALID_DEVICE_DATA` (the last one is transient) instead of a silent empty sync.

If background sync holds the device when setup verifies it, setup waits five seconds and then shows "Background sync is reading the device right now. Wait a minute and press Verify and connect again."; the cloud `errorCode` remains `DEVICE_UNREACHABLE`.

A manually entered IP falls back to UDP when TCP 4370 is refused (older UDP-only firmware). Ethernet discovery remains TCP-only. A rejected communication key shows a specific setup message while the cloud `errorCode` stays `UNSUPPORTED`.

Ethernet discovery starts after pairing and on active interface/address changes, scans one private network on TCP 4370 (at most the local /24), and requires protocol serial/size responses. The owner selects a candidate and a complete serial/user/attendance read is required before connection readiness. Manual IP/port and communication key are supported. Keys use a separate machine-DPAPI blob under the same restricted directory. Scheduled/manual operations and the setup app coordinate assigned devices through per-device OS file locks.

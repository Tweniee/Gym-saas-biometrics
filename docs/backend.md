# Backend and admin integration

Active integration lives in the authorized sibling NestJS and Angular repositories. Archived patches under integrations/reference are historical snapshots.

## Database migration

MongoDB **must be a replica set**, including for development. Pairing consumption, access changes, event ingestion/projection and checkpoint acknowledgement use transactions. A standalone Mongo instance cannot provide those guarantees and will reject these operations. Configure the existing backend's Mongo URI with the replica-set connection string.

Before enabling the routes, build the declared indexes using the repository's existing additive migration:

```sh
npm run seed:indexes
# Compiled deployment:
npm run seed:indexes:prod
```

This creates the biometric collections and unique indexes for event identities, device identities, member mappings, desired access and checkpoints. It adds a partial unique `attendances.biometricEventKey` index; legacy attendance documents need no backfill. It also registers optional `attendances.tenantId` for authoritative biometric ownership. Run the migration once per environment and after schema changes. No database migration has been executed against your configured application database by this implementation.

The existing role permissions are reused deliberately: `attendance.read` for status, `attendance.update` for setup and commands, and **both** `attendance.update` and `members.update` for mapping/access changes. Revocation additionally requires `gym_owner` or `super_admin`. Members/trainers cannot access biometric management even though they may have attendance permissions for their own history. Existing permission grants remain authoritative; no broad new owner credential or permission seed is introduced.

Every admin action resolves the requested gym using verified caller scope. Member ownership follows `Member.userGymMappingId → UserGymMapping.{tenantId,gymId}`. Connector gym and tenant come from its database identity. Native device user IDs never create or guess members.

## Routes

The real API base is `/api/v1`. Admin responses use `{success:true,data:...}`; connector protocol responses are direct JSON objects.

| Route | Purpose |
| --- | --- |
| `POST /gyms/:gym/biometric/pairing-codes` | Five-minute, single-use pairing code; issuing a replacement revokes unused previous codes |
| `POST /connectors/pair` | Atomically consume code, create unique installation, return credential once |
| `POST /connectors/token` | Exchange credential for 15-minute connector JWT |
| `POST /connectors/me/rotate-credential` | Rotate credential with a 24-hour previous-secret recovery grace |
| `GET /connectors/me/setup` | Selected gym identity and support contact |
| `POST /connectors/me/devices` | Register a locally verified device; server derives gym/connector ownership |
| `POST /biometric/releases` | Super-admin-only multipart Windows installer upload through backend StorageService |
| `GET /gyms/:gym/biometric/installer` | Latest published release metadata and SHA-256 |
| `GET /gyms/:gym/biometric/installer/:version` | Authenticated backend stream from private R2 |
| `POST /connectors/me/heartbeat` | Persist health using server receipt time |
| `GET /connectors/me/devices` | Read assigned device configurations |
| `PUT /connectors/me/devices/:device/report` | Report verified identity, separate capabilities and device reachability |
| `GET /connectors/me/commands?waitSeconds=15` | Lease one eligible command; long poll for at most 15 seconds |
| `POST /connectors/me/commands/:command/ack` | Receipt/start acknowledgement and lease renewal |
| `POST /connectors/me/commands/:command/result` | Durable device outcome, distinct from receipt |
| `POST /connectors/me/attendance/batches` | Transactional, idempotent ingestion and committed acknowledgement |
| `GET /connectors/me/devices/:device/access-state?after=...` | Current desired state, paged in groups of 200 |
| `POST /connectors/me/devices/:device/access-observed` | Confirm only the matching current state version |
| `GET /gyms/:gym/biometric/status` | Sanitized health, devices, recent commands, checkpoints and unresolved users |
| `POST /gyms/:gym/biometric/devices` | Explicitly assign a device to a connector |
| `PUT /gyms/:gym/biometric/devices/:device` | Update endpoint or reassign from a revoked connector; preserve history/timezone policy |
| `POST /gyms/:gym/biometric/connectors/:connector/discover` | Explicit supported-protocol discovery request |
| `POST /gyms/:gym/biometric/devices/:device/test` | Queue connection test |
| `POST /gyms/:gym/biometric/devices/:device/sync` | Queue manual attendance sync |
| `PUT /gyms/:gym/biometric/devices/:device/mappings` | Explicit immutable device-user/member mapping, reconcile history |
| `PUT /gyms/:gym/biometric/devices/:device/members/:member/access` | Save versioned desired access and queue command |
| `POST /gyms/:gym/biometric/connectors/:connector/revoke` | Revoke installation and expire outstanding commands |
| `POST /gyms/:gym/biometric/support-requests` | Explicit consent to save sanitized troubleshooting diagnostics |

Connector controllers bypass the **human** JWT guard and always apply `ConnectorGuard`, which checks JWT signature, HS256, issuer, audience, expiry, and live installation/tenant/gym state. Pair/token routes are explicitly public and rate limited. Connector JWT signing uses a domain-separated key derived from the existing validated `auth.jwtSecret`; connector tokens do not grant human account permissions. TLS verification and redirect rejection are enabled in the Python client.

Commands expire after one day, use 120-second renewable leases, and allow at most three attempts. Only classified transient failures retry, with a bounded backoff. Admin actions return command IDs. Angular polls status every five seconds. Revocation blocks new authenticated requests before JWT expiry and terminates waiting long polls on their next server check (within roughly one second). A device write already in progress cannot be recalled.

## Attendance integration

Raw biometric events are authoritative and idempotent per gym/device/event identity. Unknown users remain unresolved. Explicit mappings project only `check-in`/`check-out` events into `attendances`; access-granted, access-denied and unknown events retain their separate raw type. Projection uses a unique source-event key and the existing 03:00-local attendance day boundary. A stale/deleted member mapping leaves its new scans unresolved rather than losing them.

Biometric attendance also carries its source tenant/gym. Attendance lists, analytics and manager summaries filter that ownership before existing user-mapping joins, preventing a multi-gym user's scans from being exposed in another gym.

## Environment settings

`BIOMETRIC_OFFLINE_SECONDS` defaults to 180 and is bounded to 90–900 seconds. Only server heartbeat receipt determines connector freshness.

Use the existing S3/R2 storage configuration. Installer bytes are uploaded only through the backend, kept private, and proxied through the authenticated gym endpoint. Release versions are immutable and have a unique platform/version index. Upload failure does not publish a release; the same bytes/version can be retried. No installer was uploaded during local development.

No support email is drafted or sent. The setup UI directs the owner to support@thezenvore.com and shows allowlisted diagnostics.

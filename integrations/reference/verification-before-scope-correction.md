# Verification results

Verified on 19 October 2026 on macOS with Python 3.13, the existing Nest/Angular dependencies, Chrome Headless, and an isolated mongodb-memory-server replica set. No configured application database, gym LAN or physical device was used.

| Check | Result |
| --- | --- |
| Connector Python tests | 16 passed |
| Existing Identix reader tests | 20 passed |
| Backend biometric contract tests | 4 passed |
| Backend module dependency test | Passed |
| Real HTTP + Mongo replica-set + Python subprocess integration | 5 passed |
| Backend authentication architecture checks | 61 passed |
| Server error redaction | 8 passed |
| Third-party diagnostic scrubbing | 9 passed |
| Angular biometric and navigation tests, Chrome Headless | 18 passed |
| Angular development and production compilation | Passed |
| Nest compilation and TypeScript checking | Passed |
| Whitespace validation across all three repositories | Passed |

The 167-file backend prebuild run initially failed its route-authentication allowlist and two existing auth test fixtures. The allowlist was updated to enumerate the connector protocol routes and assert `ConnectorGuard`, then all 61 architecture checks passed. The two unrelated failures were reproduced separately and remain:

- `src/auth/token-revocation.spec.ts`: the refresh test omits the login-session claim now required by `AuthController.refreshToken`, producing `UnauthorizedException: Sign in again`.
- `src/tenants/tenant-delete-super-admin.spec.ts`: its JWT mock lacks the `decode` method used by `AuthService.signLoginToken`.

Those production auth paths and their test fixtures were not changed. Consequently `npm run build` remains blocked by its prebuild test command even though direct `nest build` succeeds. Other spec files passed in the broad run; affected diagnostic and architecture checks were rerun after their final changes. The full suite was not rerun after those targeted corrections.

## Recovery and isolation exercised

- Atomic concurrent pairing redemption, single use, expiration and invalid credentials.
- Cross-tenant/gym rejection for management, assigned devices and member mapping.
- Real Python client pairing and heartbeat against the HTTP API.
- Cloud commit followed by deliberately lost acknowledgement; exact persisted batch replay after starting a new Python process, without duplicate events.
- Crash boundaries around local persistence, mismatched acknowledgement and simulated disk-full errors, without checkpoint advancement.
- Unknown device users retained, explicit mapping reconciliation, and idempotent projection into existing attendance.
- Authoritative biometric gym ownership in reports and analytics for a user mapped into multiple gyms.
- Zero new scans treated as successful attendance communication.
- Shared per-device lock preventing overlapping manual/scheduled syncs.
- Command receipt distinct from success, lease recovery, stale lease rejection, and durable completion replay without repeating successful work.
- Older activation superseded by later deactivation, and desired-state recovery after a command expires.
- Simulator endpoint changes recovered by saved identity; mismatched identities rejected.
- New device generation preserves distinct events, flags a data gap, and attendance continues with unsupported access capability.
- Credential rotation recovery grace, revocation on a still-valid JWT, waiting-poll revocation and heartbeat timeout status.
- Credential/pairing/attendance bodies excluded from persisted error logs and third-party diagnostics.
- Browser UI separates connector/device/sync state, cancels old-gym responses, expires pairing codes and requires explicit support consent.

## Not executed

Windows installer compilation, executable signing, machine-DPAPI/ACL handoff, service installation, reboot/startup recovery, uninstall/upgrade/rollback; physical device attendance and access protocols; real door/expiry enforcement; resource measurements; R2 publishing; production macOS packaging; automatic membership lifecycle hooks and alert delivery.

See [production boundaries](production.md) before a gym pilot.

# Setup and acceptance testing

## Prepare the backend

Use the existing backend Mongo replica set and R2 configuration. The backend's `StorageService` handles private installer uploads and streams downloads; the browser and Windows app have no R2 credentials.

After deploying the code, run the backend's existing additive index migration:

```sh
cd ../gym_saas_backend
npm run seed:indexes
```

This is required for unique pairing/event/mapping/device/release constraints. No configured database or R2 bucket was accessed during development. Mongo transactions require a replica set.

Build/verify the Windows installer on a Windows x64 computer with Python and Inno Setup 6:

```powershell
./packaging/windows/build.ps1 -ApiUrl https://YOUR-BACKEND/api/v1
```

The manual GitHub Actions workflow can also produce the artifact. It does not publish it. Verify/sign the executable, then sign in as a super admin, open **Platform → Biometrics**, enter version **0.1.0**, and upload the executable under **Publish Windows installer**. The backend checks size, PE structure and SHA-256, uploads to private R2, and makes it available only after successful storage. PE validation is not Authenticode verification. Reusing a version for different bytes returns a conflict.

## Owner setup on Windows

1. Sign in as the gym owner and open **Members → Biometrics** (`/gym-biometrics`). Select the gym location.
2. Download the Windows app. Install it with administrator privileges on a computer on the device's Ethernet network.
3. On the admin page, generate a pairing code. Enter it in **Connector Setup** within five minutes. Codes are single-use; generating another invalidates the earlier unused code.
4. The app checks cloud authentication and scans an active Ethernet interface after pairing. Select the intended interface and use **Scan Ethernet** to retry. Scans use TCP 4370, one private network, and at most 256 addresses. A wider interface subnet is limited to its local /24. Select a candidate explicitly; the first candidate is not automatically assigned.
5. Alternatively enter the device's private IPv4 address and configured TCP port. Enter its numeric communication key locally, if required; it is protected with machine DPAPI and never sent to the backend.
6. Confirm the device's IANA timezone, initial history (today/7/30 days), and scan interpretation. **Every scan is check-in** treats scans as arrivals; **ZK codes 0 in / 1 out** requires those device semantics; **Retain without attendance** preserves raw events only. Timezone/history/policy are fixed for a device assignment.
7. Choose **Verify and connect**. The app must read a stable serial, size/user data and a recognized attendance layout. Then it registers the device using its connector-scoped identity and performs an initial upload.
8. The app and admin page report cloud pairing, device reads and acknowledged sync independently. A TCP socket, pairing code or received command alone never proves attendance success.
9. In **Link device users to gym members**, select the device, enter its enrolled user ID, search this gym, choose a member, and link it. Existing retained check-in/out scans resolve to attendance. Never guess mappings from names.
10. Keep the Windows computer awake. Closing the browser or setup window does not stop the service.

## Failure checks

- Stop the Windows service: its server heartbeat becomes offline after the configured freshness window (default 180 seconds).
- Unplug device Ethernet: the next read reports unavailable; cloud pairing stays distinct. Reconnect and use **Test** or wait for scheduled retry.
- Enter a wrong communication key or use an unrelated TCP service: setup fails without reporting connection ready.
- Expire/reuse a pairing code: pairing is rejected. Generate a new one.
- Disable internet after a staged upload: the exact pending batch survives restart and retries without duplicate attendance.
- Revoke a connector in the page: later protected requests are rejected immediately; a fresh pairing code is required.
- Device reset/log retention changes can create a gap. The system reports detectable history shrinkage and does not claim recovery of deleted logs.
- If the device uses a different protocol or unsupported record layout, contact **support@thezenvore.com** with the visible safe diagnostics. No email is drafted or sent automatically.

## Automated checks

```sh
# Connector and TCP protocol emulator, no real LAN scan
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 test_identix_manager.py -v

# Backend contract/module and isolated Mongo replica-set + HTTP/Python tests
cd ../gym_saas_backend
node -r ts-node/register -r tsconfig-paths/register --test src/biometric/biometric.spec.ts src/biometric/biometric-release.spec.ts src/biometric/biometric.module.spec.ts
npx ts-node -r tsconfig-paths/register src/biometric/biometric.integration.spec.ts

# Browser setup and role tests
cd ../Gym-saas-admin
npx ng test --watch=false --browsers=ChromeHeadless --include='src/app/views/biometric/*.spec.ts' --include='src/app/views/gym-owner-biometric/*.spec.ts' --include='src/app/guards/*admin.guard.spec.ts' --include='src/app/guards/gym-owner.guard.spec.ts'
```

The isolated backend tests use synthetic configuration, temporary MongoDB and mocked storage. They do not use real R2 or send email. Physical hardware, Windows installation/service lifecycle, signing and an actual backend-mediated R2 transfer still require deployment acceptance testing.

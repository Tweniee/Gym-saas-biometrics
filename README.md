# Identix Biometrics

A Python desktop application for viewing users on Identix biometric devices that support the ZK TCP protocol. It connects directly to the device and provides search, filters, sorting, and locally stored active/inactive status.

The application uses Python's standard library, including Tkinter. No vendor SDK or third-party Python packages are required.

For a complete first-run walkthrough, including a direct LAN cable connection, computer IP setup, connectivity checks, and automatic fetching behavior, see [RUNNING.md](RUNNING.md).

## Features

- Read device users, including UID, User ID, name, card number, role, and group.
- Search across user fields and filter by status or role.
- Sort the list by clicking column headings.
- Activate or deactivate multiple selected users in the application's local state.
- Refresh automatically with a configurable cache interval, or fetch immediately with **Refresh now**.
- Keep the current user list visible while the device is offline and retry automatically.
- Save connection settings and inactive User IDs between sessions.
- Discover open TCP ports on supplied IPv4 addresses or subnets, then select a target and fetch users.
- Record connection attempts, retries, protocol command metadata, sync results, and UI actions in rotating local logs; view them from the app.

## Requirements

- Python 3 with Tkinter installed and a graphical desktop session.
- An Identix or compatible device supporting the ZK binary protocol over TCP.
- Network access from your computer to the device's configured IP address and port (default: `4370`).
- The device's communication key, if one is configured.

The reader supports 28-byte and 72-byte user records. Compatibility depends on the device's protocol and firmware.

## Quick start

```bash
git clone https://github.com/Tweniee/Identix-biometrics.git
cd Identix-biometrics
python3 identix_manager.py
```

On Windows, you can run `py identix_manager.py` instead.

To check that Tkinter is available, run `python3 -m tkinter`; it should open a small demonstration window. If Tkinter is missing, install Tk support for your Python distribution. On Debian/Ubuntu, this is typically `sudo apt install python3-tk`.

## Connect to a device

1. Launch the application.
2. Enter the **Device IP**, **Port**, and **Comm key** shown in your device's settings.
3. Set **Cache (s)** to the desired refresh interval.
4. Click **Apply & fetch** to save the settings and request the user list.

The status line shows connection errors, the last successful sync time, and the next scheduled read. Click **Refresh now** to request a read before the cache interval expires.

The app also fetches automatically on launch using saved settings and retries failed reads. Plugging in a LAN cable does not launch the app or discover addresses. If the IP or port is uncertain, click **Discover devices**, supply your device subnet/IPs and candidate ports, then click **Start scan**. Select an open endpoint and click **Use selected & fetch**. An open TCP port is not proof of a compatible biometric device. The app reads from one selected target at a time.

### Logs

Click **View logs** to inspect `logs/identix_manager.log`, or **Refresh logs** in that window to load newer entries. Logs rotate at 2 MiB with three backups. They include application activity and connection diagnostics, not unrelated network traffic, device-side attendance events, or a list of all commands a device supports. Communication keys and raw user-record payloads are excluded; selected UIDs and User IDs changed by local status actions are included. Logs are ignored by Git.

### Configuration

Settings are stored in `identix_state.json` beside the Python script. The bundled configuration is:

```json
{
  "config": {
    "ip": "192.168.1.201",
    "port": 4370,
    "commkey": 0,
    "cache_seconds": 150
  },
  "inactive": []
}
```

| Setting | Meaning |
| --- | --- |
| `ip` | Device address; replace the sample address with your device's IP. |
| `port` | ZK TCP port, normally `4370`. |
| `commkey` | Device communication key; `0` is the default. |
| `cache_seconds` | Time between successful device reads; the UI enforces a minimum of 5 seconds. |
| `inactive` | Locally deactivated User IDs, stored as strings. |

User records are cached only in memory. Restarting the application requires a new device read; connection settings and inactive flags persist in the state file. Failed connection or read attempts are retried after a 4-second wait.

## Manage user status

Select one or more rows, then click **Activate selected** or **Deactivate selected**. Deactivation asks for confirmation. Use the **Status** filter to view active or inactive users.

**Deactivation is local to this application.** It records the User ID in `identix_state.json`; it does not update the device or prevent that user from authenticating or entering through a connected door. Device access enforcement requires a separate implementation appropriate to the device and firmware.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Waiting for connection or device offline | Confirm the device is powered on, its IP and TCP port are correct, and your computer can reach it through the network and firewall. |
| Device refused connection | Check that **Comm key** matches the device's communication key, then click **Apply & fetch**. |
| Bad packet header or unsupported user record size | Confirm the device supports the ZK TCP protocol and one of the supported user record formats. |
| Tkinter import fails or no window opens | Install Tkinter for your Python interpreter and run the application in a graphical desktop session. |

## Repository files

- `identix_manager.py` — TCP protocol client, background synchronization, and Tkinter interface.
- `identix_state.json` — saved connection settings and local inactive flags.
- `README.md` — setup and usage documentation.
- `RUNNING.md` — step-by-step LAN setup, launch instructions, and troubleshooting.
- `test_identix_manager.py` — simulated-device behavior tests (`python3 test_identix_manager.py -v`).
- `logs/identix_manager.log` — runtime diagnostics, created on launch (not committed).

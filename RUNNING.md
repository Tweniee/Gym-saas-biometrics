# Running the Identix biometric user manager

## Will users appear automatically after connecting the LAN cable?

**Yes, once the network and device settings are correct and you launch the app.** On startup, the app loads its saved settings and immediately starts trying to read users from that device. You do not need to click a button on every launch.

Connecting the cable alone does not launch the app or discover the machine's IP address. On the first run, you must make sure your computer can reach the device and enter the correct **Device IP**, **Port**, and **Comm key**. Click **Apply & fetch** after changing those fields. The app saves them for the next launch.

This project is a Python desktop app, not a browser-based gym SaaS application. It reads user records from devices supporting the **ZK binary protocol over TCP**, with 28-byte or 72-byte user records. The Identix brand alone does not guarantee compatibility with every model or firmware.

## 1. Record the machine's network settings

On the biometric machine, open its communication/network settings. Menu names vary by model. Record:

| Device setting | What to enter in the app |
| --- | --- |
| IP address | **Device IP**: the machine's actual IPv4 address. |
| Subnet mask | Used to configure your computer's Ethernet connection; there is no app field for this. |
| TCP communication port | **Port**: usually `4370`; use the device's actual port. |
| Communication key/password | **Comm key**: the numeric device communication key. Use `0` if no key is configured. This is not a user's PIN or your router password. |

If the machine has an option to enable TCP/IP communication, enable it. This app connects directly to the device's TCP port; it does not implement an ADMS/cloud push server.

The repository currently contains these sample settings:

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

The sample IP is not a detected address. Replace it with your machine's address through the app.

## 2. Connect the computer and machine

### Option A: Ethernet cable directly between them

1. Power on the biometric machine.
2. Connect its Ethernet port to your computer's Ethernet port or a USB Ethernet adapter.
3. Check that the Ethernet link is active. A cable connection does not necessarily assign IP addresses automatically.
4. In your computer's network settings, configure the **Ethernet adapter** with a manual IPv4 address in the same subnet as the machine, using a different address.

For example, if the machine is configured as follows:

| Setting | Biometric machine | Computer's Ethernet adapter |
| --- | --- | --- |
| IPv4 address | `192.168.1.201` | `192.168.1.100` |
| Subnet mask | `255.255.255.0` | `255.255.255.0` |
| Gateway and DNS | Not needed for this isolated direct link | Leave unset where supported; internet access is not required for the device connection. |

Use that example only if it matches your device's subnet, and ensure the computer's address is unused. Do not assign the machine's IP to the computer.

- **Windows:** Open the Ethernet adapter's IPv4 properties and enter the manual IP and subnet mask.
- **macOS:** Open System Settings → Network → your Ethernet adapter → Details → TCP/IP, then configure IPv4 manually.
- **Linux:** Open the wired connection's IPv4 settings and select manual addressing. A mask of `255.255.255.0` corresponds to prefix `/24`.

If Wi-Fi and Ethernet use the same subnet, routing can send traffic through the wrong adapter. Temporarily disconnect Wi-Fi to diagnose this, or configure a distinct subnet for the direct link on both the machine and computer. Restore your normal Ethernet configuration when you finish using the isolated link.

### Option B: Both connected through a router or switch

Connect the computer and machine to the same LAN. A computer on Wi-Fi can also connect if the router permits communication with wired devices. Make sure their addresses and subnet masks permit communication, and that guest-network or client-isolation settings do not block it. Avoid duplicate IP addresses. If the machine uses DHCP, reserve its address or update the app when that address changes.

## 3. Check connectivity

Replace the sample address and port in these commands with your actual device settings.

**Windows PowerShell:**

```powershell
ping 192.168.1.201
Test-NetConnection -ComputerName 192.168.1.201 -Port 4370
```

For the TCP check, look for `TcpTestSucceeded : True`.

**macOS or Linux:**

```bash
ping -c 4 192.168.1.201
nc -vz -w 3 192.168.1.201 4370
```

The `nc` check requires netcat to be installed. An open TCP port confirms reachability, but does not confirm the communication key or protocol compatibility. Some machines do not answer ping; a failed ping alone does not prove the TCP connection will fail.

If the TCP test fails, check the cable/link, power, IP address, subnet, port, routing, and firewall rules before expecting users to appear.

## 4. Check Python and Tkinter

Run this project on a computer with a graphical desktop session and Python 3 with Tkinter. It uses only Python's standard library; there is no `requirements.txt`, vendor SDK, or third-party package installation step.

**Windows:**

```powershell
py --version
py -m tkinter
```

**macOS or Linux:**

```bash
python3 --version
python3 -m tkinter
```

The Tkinter command should open a small demonstration window. Close it before continuing.

If Tkinter is unavailable:

- **Windows:** Install or modify Python with Tcl/Tk support enabled.
- **macOS:** Use a Python installation with Tk support, such as the installer from python.org. For another distribution, install the matching Tk support for that interpreter.
- **Debian/Ubuntu:** Install the system Tkinter package with `sudo apt install python3-tk` and use the matching system Python.

## 5. Launch the app and fetch users

Open a terminal in the repository directory containing `identix_manager.py`.

**Windows:**

```powershell
py identix_manager.py
```

**macOS or Linux:**

```bash
python3 identix_manager.py
```

For this checkout on your Mac, you can use:

```bash
cd "/Users/dhirajsingh/Desktop/Github/Gym Saas/Gym-saas-biometrics"
python3 identix_manager.py
```

The **Identix User Manager** window opens and starts a background fetch using the saved settings.

On the first run, or when changing machines:

1. Enter the actual **Device IP**.
2. Enter the correct **Port** and numeric **Comm key**.
3. Set **Cache (s)** to the refresh interval you want. The default is `150` seconds (2 minutes 30 seconds); applying settings enforces a minimum of `5` seconds.
4. Click **Apply & fetch**. Editing the fields alone does not apply them. **Refresh now** uses the settings already applied.
5. Wait for the read to finish. The bottom status line should show **Synced**, a time, the target IP/port, and a countdown to the next read.

After a successful read, the table displays **UID**, **User ID**, **Name**, **Card**, **Role**, **Group**, and the app's local **Status**. A machine with no enrolled users can sync successfully with an empty table. Names and card numbers depend on what is stored on the machine.

Use **Clear** to reset search and filters if expected users are hidden. Use **Refresh now** to request a new read before the interval expires.

## 6. What happens on later launches and disconnections?

| Situation | App behavior |
| --- | --- |
| Launch with correct saved settings and a reachable compatible device | Automatically fetches the user list. |
| Launch before the cable is connected or machine is powered on | Keeps checking the saved target; fetches automatically once it can connect and read successfully. |
| Successful fetch while the app stays open | Reads again after the configured cache interval. This is polling, not an instant live event feed. |
| Add/enroll a user on the machine | Appears after the next successful read, or after **Refresh now**. |
| Device disconnects after a successful read | When the next read is due, reports the failure and keeps the last fetched list visible in memory. |
| Connection or read fails | Waits 4 seconds between attempts; network timeouts can make the actual interval longer. |
| Close and reopen the app | Loads settings and inactive flags, then performs a fresh device read. The previous user list is not saved to disk. |

The status line is based on the latest read/probe result. It may still show the last successful sync until another read detects a disconnection. The app must remain open for automatic refresh and retries to continue.

## 7. Saved settings and user status

The app stores connection settings and locally inactive User IDs in `identix_state.json` beside the script. The repository directory must be writable to save changes. The communication key is stored as plain JSON, so keep this file private if you configure a key.

**Activate selected** and **Deactivate selected** change only the local status in this app. They do not disable a user on the biometric machine, prevent authentication, or enforce gym membership/access rules. A displayed **Active** status is not a device access-permission check.

This project displays user records. It does not currently provide attendance-log syncing, fingerprint-template backup, automatic network discovery, device enrollment, or device-side access enforcement.

## Troubleshooting

| What you see | What to do |
| --- | --- |
| No window / Tkinter import error | Verify Tkinter with the same Python command used to launch the app, and run it in a graphical desktop session. |
| `Waiting for first connection` or `Device offline ... no data yet` | Verify power, cable, Ethernet addressing, target IP/port, routing, and TCP reachability. Apply corrected settings. |
| `Device refused connection (check comm key)` | Verify the device's numeric communication key and click **Apply & fetch**. |
| `Bad packet header (not a ZK-protocol device?)` | Confirm the selected port speaks the ZK binary TCP protocol. A reachable ADMS/web port is not sufficient. |
| `Could not determine user record size`, unsupported record format, unexpected replies, or repeated read failures | Check model/firmware protocol compatibility. The current reader handles 28-byte and 72-byte user records; another format may require code changes. |
| Synced but no rows | Check enrolled users on the machine, confirm you connected to the intended device, and click **Clear** to remove filters. |
| Newly enrolled user missing | Click **Refresh now** or wait for the next successful read. |
| Old rows still visible while offline | These are cached rows from the last successful read during this session. Check the bottom status line. |
| Settings fail to save | Check write permission for the directory containing `identix_state.json`. |

These instructions describe the behavior implemented in `identix_manager.py`. A successful read from your specific machine still needs to be verified with that machine connected; no physical-device compatibility test is implied by this guide.

"""Desktop pairing wizard; all network I/O runs off the Tk thread."""
import ipaddress
import json
import queue
import sys
import threading
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from . import __version__
from .adapters import adapter_for
from .auth import CredentialStore
from .discovery import interfaces
from .pairing import ServerConnection
from .runtime import error_code
from .sync import utc_now

SUPPORT = "support@thezenvore.com"


def show(runtime, config_path=None):
    import tkinter as tk
    from tkinter import ttk, font
    root = tk.Tk()
    native_font = font.nametofont("TkDefaultFont").actual("family")
    root.title("Zenvore · Biometric Connector")
    root.geometry("860x" + str(min(760, root.winfo_screenheight() - 100)))
    root.minsize(700, 550)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    canvas = tk.Canvas(root, highlightthickness=0)
    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas.configure(yscrollcommand=scrollbar.set)
    frame = ttk.Frame(canvas, padding=24)
    window = canvas.create_window((0, 0), window=frame, anchor="nw")
    frame.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
    frame.columnconfigure(1, weight=1)
    ttk.Label(frame, text="Connect your gym", font=(native_font, 20, "bold")).grid(row=0, column=0, columnspan=3, sticky="w")
    ttk.Label(frame, text=("macOS connector " if sys.platform == "darwin" else "Windows connector ") + __version__ + " · Identix / ZK-compatible TCP").grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 14))
    cloud_status = tk.StringVar(value="Cloud: checking pairing…")
    device_status = tk.StringVar(value="Device: not verified")
    sync_status = tk.StringVar(value="Attendance: not started")
    for row, variable in enumerate((cloud_status, device_status, sync_status), start=2):
        ttk.Label(frame, textvariable=variable, wraplength=710).grid(row=row, column=0, columnspan=3, sticky="w", pady=3)
    ttk.Separator(frame).grid(row=5, column=0, columnspan=3, sticky="ew", pady=14)
    ttk.Label(frame, text="1. Pair with Zenvore", font=(native_font, 12, "bold")).grid(row=6, column=0, columnspan=3, sticky="w")
    ttk.Label(frame, text="Generate a 5-minute pairing code on your gym's Biometrics page.").grid(row=7, column=0, columnspan=3, sticky="w")
    code = ttk.Entry(frame, show="•", width=24)
    code.grid(row=8, column=0, columnspan=2, sticky="ew", pady=8)
    messages = queue.Queue()
    busy = False
    server = ServerConnection(runtime)
    pairing_required = True
    closed = threading.Event()
    def work(kind, action):
        def execute():
            try:
                messages.put((kind, action(), None))
            except Exception as exc:
                messages.put((kind, None, error_code(exc)))
        threading.Thread(target=execute, daemon=True).start()
    def pair():
        nonlocal busy
        if busy or polling:
            return
        value = code.get().strip()
        if pairing_required and not value:
            note.set("Enter the 5-minute pairing code from your gym's Biometrics page.")
            return
        busy = True
        pair_button.configure(state="disabled")
        note.set("Pairing with your gym…" if pairing_required else "Reconnecting with your saved pairing…")
        work("pair", lambda: server.pair(value))
    pair_button = ttk.Button(frame, text="Pair app", command=pair)
    pair_button.grid(row=8, column=2, padx=(12, 0))
    ttk.Label(frame, text="2. Find your Ethernet device", font=(native_font, 12, "bold")).grid(row=9, column=0, columnspan=3, sticky="w", pady=(14, 6))
    # Enumerate local interfaces only after the server pairing is established.
    nics = []
    choices = []
    nic = ttk.Combobox(frame, state="readonly", values=choices)
    nic.grid(row=10, column=0, columnspan=2, sticky="ew")
    preferred = None
    candidates = []
    candidate = ttk.Combobox(frame, state="readonly")
    candidate.grid(row=11, column=0, columnspan=3, sticky="ew", pady=8)
    def scan():
        nonlocal busy
        if busy:
            return
        selected = nic.current()
        if selected < 0:
            note.set("Select an active Ethernet interface, or enter the IP and port manually.")
            return
        busy = True
        note.set("Scanning the selected network (up to 256 addresses, TCP 4370)…")
        work("scan", lambda: runtime.discover([nics[selected]]))
    ttk.Button(frame, text="Scan Ethernet", command=scan).grid(row=10, column=2, padx=(12, 0))
    ip = ttk.Entry(frame, width=24)
    port = ttk.Entry(frame, width=9)
    port.insert(0, "4370")
    key = ttk.Entry(frame, width=18, show="•")
    for column, text, entry in ((0, "Device IP", ip), (1, "Port", port), (2, "Communication key (0 if none)", key)):
        ttk.Label(frame, text=text).grid(row=12, column=column, sticky="w")
        entry.grid(row=13, column=column, sticky="ew", padx=(0, 10), pady=(3, 8))
    def selected(_event=None):
        if candidate.current() >= 0:
            value = candidates[candidate.current()]
            ip.delete(0, "end"); ip.insert(0, value["ip"])
            port.delete(0, "end"); port.insert(0, str(value["port"]))
    candidate.bind("<<ComboboxSelected>>", selected)
    ttk.Label(frame, text="3. Verify device data and start attendance", font=(native_font, 12, "bold")).grid(row=14, column=0, columnspan=3, sticky="w", pady=(10, 8))
    ttk.Label(frame, text="Device timezone (IANA)").grid(row=15, column=0, sticky="w")
    zone = ttk.Entry(frame)
    zone.insert(0, "Asia/Kolkata")
    zone.grid(row=16, column=0, sticky="ew", padx=(0, 10))
    ttk.Label(frame, text="Initial history").grid(row=15, column=1, sticky="w")
    history = ttk.Combobox(frame, state="readonly", values=["Today", "Last 7 days", "Last 30 days"])
    history.current(0)
    history.grid(row=16, column=1, sticky="ew", padx=(0, 10))
    ttk.Label(frame, text="Scan interpretation").grid(row=15, column=2, sticky="w")
    policy = ttk.Combobox(frame, state="readonly", values=["Every scan is check-in", "ZK codes: 0 in / 1 out", "Retain without attendance"])
    policy.current(0)
    policy.grid(row=16, column=2, sticky="ew")
    note = tk.StringVar(value="Pair with the server first. You can connect the biometric device later.")
    ttk.Label(frame, textvariable=note, wraplength=720).grid(row=18, column=0, columnspan=3, sticky="w", pady=12)
    def connect():
        nonlocal busy
        if busy:
            return
        try:
            address = str(ipaddress.IPv4Address(ip.get().strip()))
            if not ipaddress.ip_address(address).is_private or ipaddress.ip_address(address).is_loopback:
                raise ValueError()
            number = int(port.get())
            password = int(key.get() or "0")
            if not 1 <= number <= 65535 or not 0 <= password <= 0xffffffff:
                raise ValueError()
            timezone_name = zone.get().strip()
            ZoneInfo(timezone_name)
            days = (0, 7, 30)[history.current()]
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=days) if days else now.astimezone(ZoneInfo(timezone_name)).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
            event_policy = ("check-in", "zk-in-out", "unknown")[policy.current()]
        except (ValueError, KeyError):
            note.set("Enter a private IPv4 address, valid port, numeric communication key and IANA timezone.")
            return
        key.delete(0, "end")
        busy = True
        note.set("Verifying serial number, user records and attendance data…")
        def configure():
            runtime.cloud.request("GET", "/connectors/me/setup")  # Authentication gates device configuration.
            secrets = CredentialStore(runtime.config.state_dir, runtime.config.development, "devices.credential")
            values = secrets.load() or {}
            values[address + ":" + str(number)] = password
            secrets.save(values)
            device = {"adapter": "zk-tcp", "ip": address, "port": number, "timezone": timezone_name,
                      "historySince": start.isoformat(), "eventPolicy": event_policy}
            adapter = adapter_for(device, runtime.config, runtime.store)
            identity = adapter.health()
            result = runtime.cloud.request("POST", "/connectors/me/devices", {**device, "expectedIdentity": identity})
            device["_id"] = result["deviceId"]
            # Fetch the canonical configuration on retries, retaining its history/time policy.
            saved = runtime.cloud.request("GET", "/connectors/me/devices")
            device = next(d for d in saved if d["_id"] == result["deviceId"])
            with runtime.locks.for_device(device["_id"]):
                adapter = runtime.handshake(device)
                runtime.sync.run(device, adapter)
            runtime.heartbeat_once()
            return identity
        work("connect", configure)
    ttk.Button(frame, text="Verify and connect", command=connect).grid(row=17, column=0, columnspan=2, sticky="w", pady=(16, 0))
    diagnostics = tk.Text(frame, height=4, width=85, state="disabled", wrap="word")
    diagnostics.grid(row=19, column=0, columnspan=3, sticky="ew")
    ttk.Label(frame, text="Need help? Contact " + SUPPORT + ". No email is sent automatically.\nKeep this computer awake. Closing setup does not stop background sync when enabled.", wraplength=720).grid(row=20, column=0, columnspan=3, sticky="w", pady=10)
    if sys.platform == "darwin":
        from .macos_service import MacService
        service = MacService(config_path or runtime.config.state_dir / "config.json")
        def service_action(enable):
            nonlocal busy
            if busy:
                return
            busy = True
            work("service", service.enable if enable else service.disable)
        ttk.Button(frame, text="Enable background sync", command=lambda: service_action(True)).grid(row=21, column=0, sticky="w", pady=8)
        ttk.Button(frame, text="Disable background sync", command=lambda: service_action(False)).grid(row=21, column=1, sticky="w", pady=8)
    polling = False
    device_polling = False
    auto_scanned = False
    def server_status(result):
        nonlocal pairing_required, device_polling
        pairing_required = result.needs_pairing
        pair_button.configure(text="Pair app" if pairing_required else "Retry server connection", state="normal")
        code.configure(state="normal" if pairing_required else "disabled")
        if result.paired and not pairing_required:
            code.configure(state="normal")
            code.delete(0, "end")
            code.configure(state="disabled")
        if result.setup is not None:
            cloud_status.set("Cloud: connected · " + (result.setup.get("gymName") or result.setup["gymId"]) + " · Pairing saved securely")
            if not device_polling and not busy:
                device_polling = True
                work("status", lambda: (runtime.cloud.request("GET", "/connectors/me/devices"), interfaces()))
        elif pairing_required:
            cloud_status.set("Cloud: pairing required" + (" (" + result.error + ")" if result.error else ""))
        else:
            cloud_status.set("Cloud: pairing saved · Reconnecting (" + result.error + "). No new pairing code needed.")
    def refresh():
        nonlocal polling
        if not closed.is_set() and not polling and not busy:
            polling = True
            pair_button.configure(state="disabled")
            work("server", server.check)
        if not closed.is_set():
            root.after(5000, refresh)
    def poll():
        nonlocal busy, polling, device_polling, candidates, auto_scanned, nics, choices, preferred
        try:
            while True:
                kind, result, error = messages.get_nowait()
                if kind == "server":
                    polling = False
                    if error:
                        pair_button.configure(state="normal")
                        cloud_status.set("Cloud: secure pairing could not be checked (" + error + "). Unlock credential storage and retry.")
                    else:
                        server_status(result)
                elif kind == "status":
                    device_polling = False
                    if error:
                        device_status.set("Device: current status unavailable")
                    else:
                        devices, active_nics = result
                        if active_nics != nics:
                            old = nic.get()
                            nics = active_nics
                            choices = [i["name"] + " · " + i["address"] for i in nics]
                            nic.configure(values=choices)
                            preferred = next((i for i, item in enumerate(nics) if item["selectedByDefault"]), None)
                            if old in choices:
                                nic.current(choices.index(old))
                            elif preferred is not None:
                                nic.current(preferred)
                            else:
                                nic.set("")
                            auto_scanned = False
                        fresh = [d for d in devices if d.get("report", {}).get("reachable") and d["report"].get("receivedAt") and
                                 (datetime.now(timezone.utc) - datetime.fromisoformat(d["report"]["receivedAt"].replace("Z", "+00:00"))).total_seconds() < 180]
                        device_status.set("Device: connection ready · " + fresh[0]["identity"] if fresh else "Device: waiting for a successful data read")
                        health = runtime.store.get("health", {})
                        synced = health.get("lastAcknowledgedUpload")
                        sync_status.set(("Attendance: last cloud acknowledgement " + synced if synced else "Attendance: no acknowledged upload yet") + (" · History gap detected" if health.get("errorCode") == "DATA_GAP" else ""))
                        if not devices and not auto_scanned and preferred is not None:
                            auto_scanned = True
                            scan()
                else:
                    busy = False
                    if kind == "pair":
                        pair_button.configure(state="normal")
                    if error and kind == "service":
                        note.set("Background sync could not be changed. Open the app from Applications, check System Settings → General → Login Items, and retry (" + error + ").")
                    elif error:
                        note.set(("Server pairing could not complete (" + error + "). Check internet access and secure credential storage, then retry. A saved pairing is retained." if kind == "pair" else "Setup did not complete (" + error + "). Check Ethernet, IP/port and communication key, then retry. Contact " + SUPPORT + " if needed."))
                        diagnostics.configure(state="normal"); diagnostics.delete("1.0", "end")
                        diagnostics.insert("1.0", json.dumps({"time": utc_now(), "appVersion": __version__, "operation": kind, "errorCode": error,
                                                          "ip": ip.get(), "port": port.get(), "timezone": zone.get()}, indent=2))
                        diagnostics.configure(state="disabled")
                    elif kind == "service":
                        note.set(result)
                    elif kind == "pair":
                        server_status(result)
                        if result.setup is not None:
                            note.set("Server connected and pairing saved securely. You can configure or fix the device TCP connection later.")
                        elif result.needs_pairing:
                            note.set("Server rejected authentication. Check the connector in Zenvore Admin before pairing again.")
                        else:
                            note.set("Pairing saved securely. The app will retry the server connection automatically; no new code is needed.")
                    elif kind == "scan":
                        candidates = result
                        candidate.configure(values=[d["identity"] + " · " + d["ip"] + ":" + str(d["port"]) for d in candidates])
                        candidate.set("")
                        note.set("Choose a verified candidate, or enter the address manually." if candidates else "No compatible device answered. Check Ethernet and the communication key, or enter the IP and port manually.")
                    elif kind == "connect":
                        note.set("Connection ready · " + result + ". First upload acknowledged. Map device user IDs to members in Zenvore Admin.")
                        device_status.set("Device: connection ready · " + result)
                        sync_status.set("Attendance: upload acknowledged")
        except queue.Empty:
            pass
        if not closed.is_set():
            root.after(200, poll)
    def close():
        closed.set()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    refresh()
    poll()
    root.mainloop()

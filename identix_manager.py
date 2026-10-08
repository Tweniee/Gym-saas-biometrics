#!/usr/bin/env python3
"""
Identix biometric user manager  --  standard library only (socket, struct, tkinter).

What it does
  * Talks to the device directly over TCP using the ZK binary protocol
    (default port 4370) -- no third-party / vendor packages.
  * Keeps the user list IN MEMORY and only re-reads the device when the cache is
    older than CACHE_SECONDS (default 150 s = 2.5 min), or when you press Refresh.
  * If the device is unreachable when a refresh is due, it keeps showing the cached
    list and waits; as soon as the TCP port answers, it re-fetches automatically.
  * UI: search, filter (status / role), click-to-sort columns.
  * Activate / Deactivate users. This flag lives in YOUR system (identix_state.json),
    keyed by User ID -- see NOTE at the bottom about enforcing it on the device.

Run:  python identix_manager.py
"""

import json
import os
import queue
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

# --------------------------------------------------------------------------- #
#  Settings (editable in the UI too; saved to identix_state.json)
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {"ip": "192.168.1.201", "port": 4370, "commkey": 0, "cache_seconds": 150}
RETRY_SECONDS = 4          # how often to probe the port while the device is offline
SOCKET_TIMEOUT = 8
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "identix_state.json")

# --------------------------------------------------------------------------- #
#  ZK protocol (TCP framing)
# --------------------------------------------------------------------------- #
MAGIC = b"\x50\x50\x82\x7d"
CMD_CONNECT, CMD_EXIT = 1000, 1001
CMD_AUTH = 1102
CMD_USERTEMP_RRQ = 9
CMD_GET_FREE_SIZES = 50
CMD_PREPARE_DATA, CMD_DATA, CMD_FREE_DATA = 1500, 1501, 1502
CMD_PREPARE_BUFFER, CMD_READ_BUFFER = 1503, 1504
CMD_ACK_OK, CMD_ACK_ERROR, CMD_ACK_DATA, CMD_ACK_UNAUTH = 2000, 2001, 2002, 2005
FCT_USER = 5
CHUNK = 0xFFC0
OK_CODES = (CMD_ACK_OK, CMD_ACK_DATA)


class DeviceError(Exception):
    pass


def checksum(buf: bytes) -> int:
    s, n, i = 0, len(buf), 0
    while n > 1:
        s += buf[i] | (buf[i + 1] << 8)
        if s > 0xFFFF:
            s -= 0xFFFF
        i += 2
        n -= 2
    if n:
        s += buf[i]
    while s > 0xFFFF:
        s -= 0xFFFF
    return (~s) & 0xFFFF


def make_commkey(key: int, session_id: int, ticks: int = 50) -> bytes:
    k = 0
    for i in range(32):
        k = (k << 1 | 1) if key & (1 << i) else (k << 1)
    k = (k + session_id) & 0xFFFFFFFF
    b = struct.unpack("<4B", struct.pack("<I", k))
    b = bytes([b[0] ^ ord("Z"), b[1] ^ ord("K"), b[2] ^ ord("S"), b[3] ^ ord("O")])
    h = struct.unpack("<2H", b)
    b = struct.pack("<2H", h[1], h[0])
    t = ticks & 0xFF
    b = struct.unpack("<4B", b)
    return bytes([b[0] ^ t, b[1] ^ t, t, b[3] ^ t])


def port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


ROLES = {0: "User", 14: "Admin"}


def parse_users(body: bytes, rec_size: int):
    users = []
    if rec_size == 72:
        fmt = struct.Struct("<HB8s24sIx7sx24s")
        for off in range(0, len(body) - 71, 72):
            uid, priv, _pw, name, card, group, user_id = fmt.unpack_from(body, off)
            users.append({
                "uid": uid,
                "user_id": user_id.split(b"\x00")[0].decode("utf-8", "ignore"),
                "name": name.split(b"\x00")[0].decode("utf-8", "ignore").strip(),
                "card": str(card) if card else "",
                "role": ROLES.get(priv, f"Level {priv}"),
                "group": group.split(b"\x00")[0].decode("utf-8", "ignore"),
            })
    elif rec_size == 28:
        fmt = struct.Struct("<HB5s8sIxBhI")
        for off in range(0, len(body) - 27, 28):
            uid, priv, _pw, name, card, group, _tz, user_id = fmt.unpack_from(body, off)
            users.append({
                "uid": uid,
                "user_id": str(user_id),
                "name": name.split(b"\x00")[0].decode("utf-8", "ignore").strip(),
                "card": str(card) if card else "",
                "role": ROLES.get(priv, f"Level {priv}"),
                "group": str(group),
            })
    else:
        raise DeviceError(f"Unsupported user record size: {rec_size}")
    return users


class Device:
    def __init__(self, ip, port, commkey=0):
        self.ip, self.port, self.commkey = ip, int(port), int(commkey)
        self.sock = None
        self.session_id = 0
        self.reply_id = 0xFFFF - 1

    # ---- low level -------------------------------------------------------- #
    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            part = self.sock.recv(n - len(buf))
            if not part:
                raise DeviceError("Connection closed by device")
            buf += part
        return bytes(buf)

    def _recv_packet(self):
        head = self._recv_exact(8)
        if head[:4] != MAGIC:
            raise DeviceError("Bad packet header (not a ZK-protocol device?)")
        size = struct.unpack("<I", head[4:])[0]
        body = self._recv_exact(size)
        cmd, _chk, sess, rid = struct.unpack("<4H", body[:8])
        return cmd, sess, rid, body[8:]

    def _drain(self):
        self.sock.settimeout(0.05)
        try:
            while self.sock.recv(65536):
                pass
        except (socket.timeout, BlockingIOError):
            pass
        finally:
            self.sock.settimeout(SOCKET_TIMEOUT)

    def _build(self, command, data=b""):
        buf = struct.pack("<4H", command, 0, self.session_id, self.reply_id) + data
        chk = checksum(buf)
        rid = self.reply_id + 1
        if rid >= 0xFFFF:
            rid -= 0xFFFF
        pkt = struct.pack("<4H", command, chk, self.session_id, rid) + data
        return MAGIC + struct.pack("<I", len(pkt)) + pkt

    def _cmd(self, command, data=b""):
        self._drain()
        self.sock.sendall(self._build(command, data))
        cmd, sess, rid, payload = self._recv_packet()
        if command == CMD_CONNECT:
            self.session_id = sess
        self.reply_id = rid
        return cmd, payload

    # ---- session ---------------------------------------------------------- #
    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=SOCKET_TIMEOUT)
        self.sock.settimeout(SOCKET_TIMEOUT)
        cmd, _ = self._cmd(CMD_CONNECT)
        if cmd == CMD_ACK_UNAUTH:
            cmd, _ = self._cmd(CMD_AUTH, make_commkey(self.commkey, self.session_id))
        if cmd not in OK_CODES:
            raise DeviceError("Device refused connection (check comm key)")

    def close(self):
        if self.sock:
            try:
                self._cmd(CMD_EXIT)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ---- bulk reads ------------------------------------------------------- #
    def _read_chunk(self, start, size):
        cmd, payload = self._cmd(CMD_READ_BUFFER, struct.pack("<ii", start, size))
        if cmd == CMD_DATA:
            return payload
        if cmd != CMD_PREPARE_DATA:
            raise DeviceError(f"Unexpected reply {cmd} while reading data")
        expected = struct.unpack("<I", payload[:4])[0]
        buf = bytearray()
        while len(buf) < expected:
            c, _s, _r, p = self._recv_packet()
            if c == CMD_DATA:
                buf += p
            elif c == CMD_ACK_ERROR:
                raise DeviceError("Device returned an error while sending data")
        self.sock.settimeout(0.5)          # swallow the trailing ACK if it comes
        try:
            self._recv_packet()
        except (socket.timeout, DeviceError):
            pass
        finally:
            self.sock.settimeout(SOCKET_TIMEOUT)
        return bytes(buf)

    def _read_buffer(self, command, fct):
        cmd, payload = self._cmd(CMD_PREPARE_BUFFER, struct.pack("<bhii", 1, command, fct, 0))
        if cmd == CMD_DATA:
            return payload
        if cmd not in (CMD_PREPARE_DATA, CMD_ACK_OK):     # devices answer with either
            raise DeviceError(f"Unexpected reply {cmd} when requesting data")
        total = struct.unpack("<I", payload[1:5])[0]
        out, start = bytearray(), 0
        while start < total:
            size = min(CHUNK, total - start)
            out += self._read_chunk(start, size)
            start += size
        self._cmd(CMD_FREE_DATA)
        return bytes(out)

    def get_users(self):
        count = None
        try:
            cmd, p = self._cmd(CMD_GET_FREE_SIZES)
            if cmd in OK_CODES and len(p) >= 20:
                count = struct.unpack("<5i", p[:20])[4]
        except Exception:
            pass
        if count == 0:
            return []
        data = self._read_buffer(CMD_USERTEMP_RRQ, FCT_USER)
        total = struct.unpack("<I", data[:4])[0]
        body = data[4:4 + total]
        if not body:
            return []
        rec = None
        if count and len(body) % count == 0 and len(body) // count in (28, 72):
            rec = len(body) // count
        elif len(body) % 72 == 0:
            rec = 72
        elif len(body) % 28 == 0:
            rec = 28
        if rec is None:
            raise DeviceError("Could not determine user record size")
        return parse_users(body, rec)

    def fetch_users(self):
        try:
            self.connect()
            return self.get_users()
        finally:
            self.close()


# --------------------------------------------------------------------------- #
#  Local state (config + active/inactive flags)
# --------------------------------------------------------------------------- #
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(s.get("config", {}))
    return cfg, set(s.get("inactive", []))


def save_state(cfg, inactive):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"config": cfg, "inactive": sorted(inactive)}, f, indent=2)
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------- #
#  Background sync worker: cache TTL + wait-for-device logic
# --------------------------------------------------------------------------- #
class SyncWorker(threading.Thread):
    def __init__(self, get_cfg, out_q):
        super().__init__(daemon=True)
        self.get_cfg, self.q = get_cfg, out_q
        self.force = threading.Event()
        self.wake = threading.Event()
        self.last_sync = None

    def refresh_now(self):
        self.force.set()
        self.wake.set()

    def _sleep(self, secs):
        self.wake.wait(secs)
        self.wake.clear()

    def run(self):
        while True:
            cfg = self.get_cfg()
            age = None if self.last_sync is None else time.time() - self.last_sync
            due = self.force.is_set() or age is None or age >= cfg["cache_seconds"]
            if not due:
                self._sleep(1)
                continue
            if not port_open(cfg["ip"], cfg["port"]):
                self.q.put(("offline", None))          # keep cache, keep waiting
                self._sleep(RETRY_SECONDS)
                continue
            try:
                users = Device(cfg["ip"], cfg["port"], cfg["commkey"]).fetch_users()
                self.last_sync = time.time()
                self.force.clear()
                self.q.put(("users", users, self.last_sync))
            except Exception as e:                     # noqa: BLE001
                self.q.put(("error", str(e)))
                self._sleep(RETRY_SECONDS)


# --------------------------------------------------------------------------- #
#  UI
# --------------------------------------------------------------------------- #
COLUMNS = [("uid", "UID", 60), ("user_id", "User ID", 110), ("name", "Name", 230),
           ("card", "Card", 110), ("role", "Role", 90), ("group", "Group", 70),
           ("status", "Status", 90)]


def sort_key(v):
    s = str(v)
    return (0, int(s), "") if s.isdigit() else (1, 0, s.lower())


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Identix User Manager")
        self.geometry("920x600")
        self.cfg, self.inactive = load_state()
        self.cfg_lock = threading.Lock()
        self.users = []
        self.last_sync = None
        self.conn_state = "waiting"      # waiting | online | offline | error
        self.last_error = ""
        self.sort_col, self.sort_rev = "uid", False
        self.q = queue.Queue()
        self._build_ui()
        self.worker = SyncWorker(self._cfg_snapshot, self.q)
        self.worker.start()
        self.after(200, self._poll_queue)
        self.after(1000, self._tick)

    # ---- config ----------------------------------------------------------- #
    def _cfg_snapshot(self):
        with self.cfg_lock:
            return dict(self.cfg)

    def _apply_config(self):
        try:
            new = {"ip": self.v_ip.get().strip(), "port": int(self.v_port.get()),
                   "commkey": int(self.v_key.get()),
                   "cache_seconds": max(5, int(self.v_cache.get()))}
        except ValueError:
            messagebox.showerror("Invalid settings", "Port, comm key and cache must be numbers.")
            return
        with self.cfg_lock:
            self.cfg = new
        save_state(new, self.inactive)
        self.worker.refresh_now()

    # ---- layout ----------------------------------------------------------- #
    def _build_ui(self):
        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        self.v_ip = tk.StringVar(value=self.cfg["ip"])
        self.v_port = tk.StringVar(value=str(self.cfg["port"]))
        self.v_key = tk.StringVar(value=str(self.cfg["commkey"]))
        self.v_cache = tk.StringVar(value=str(self.cfg["cache_seconds"]))
        for label, var, w in (("Device IP", self.v_ip, 15), ("Port", self.v_port, 6),
                              ("Comm key", self.v_key, 7), ("Cache (s)", self.v_cache, 6)):
            ttk.Label(top, text=label).pack(side="left", padx=(0, 3))
            ttk.Entry(top, textvariable=var, width=w).pack(side="left", padx=(0, 10))
        ttk.Button(top, text="Apply & fetch", command=self._apply_config).pack(side="left")
        ttk.Button(top, text="Refresh now", command=self.worker_refresh).pack(side="left", padx=6)

        flt = ttk.Frame(self, padding=(8, 8, 8, 0))
        flt.pack(fill="x")
        ttk.Label(flt, text="Search").pack(side="left", padx=(0, 3))
        self.v_search = tk.StringVar()
        self.v_search.trace_add("write", lambda *_: self.refresh_view())
        ttk.Entry(flt, textvariable=self.v_search, width=30).pack(side="left", padx=(0, 12))
        ttk.Label(flt, text="Status").pack(side="left", padx=(0, 3))
        self.v_status = tk.StringVar(value="All")
        cb = ttk.Combobox(flt, textvariable=self.v_status, width=9, state="readonly",
                          values=["All", "Active", "Inactive"])
        cb.pack(side="left", padx=(0, 12))
        cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh_view())
        ttk.Label(flt, text="Role").pack(side="left", padx=(0, 3))
        self.v_role = tk.StringVar(value="All")
        self.cb_role = ttk.Combobox(flt, textvariable=self.v_role, width=10, state="readonly",
                                    values=["All"])
        self.cb_role.pack(side="left")
        self.cb_role.bind("<<ComboboxSelected>>", lambda _e: self.refresh_view())
        ttk.Button(flt, text="Clear", command=self._clear_filters).pack(side="left", padx=10)

        mid = ttk.Frame(self, padding=8)
        mid.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(mid, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="extended")
        for key, text, width in COLUMNS:
            self.tree.heading(key, text=text, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, anchor="w")
        self.tree.tag_configure("inactive", foreground="#9a9a9a")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        act = ttk.Frame(self, padding=(8, 0, 8, 4))
        act.pack(fill="x")
        ttk.Button(act, text="Activate selected", command=lambda: self.set_active(True)).pack(side="left")
        ttk.Button(act, text="Deactivate selected", command=lambda: self.set_active(False)).pack(side="left", padx=6)
        self.lbl_count = ttk.Label(act, text="")
        self.lbl_count.pack(side="right")

        self.lbl_conn = ttk.Label(self, text="Waiting for first connection...", padding=(8, 2, 8, 8))
        self.lbl_conn.pack(fill="x")
        self._update_headings()

    def worker_refresh(self):
        self.worker.refresh_now()

    def _clear_filters(self):
        self.v_search.set("")
        self.v_status.set("All")
        self.v_role.set("All")
        self.refresh_view()

    # ---- sorting / filtering ---------------------------------------------- #
    def sort_by(self, col):
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        self._update_headings()
        self.refresh_view()

    def _update_headings(self):
        for key, text, _w in COLUMNS:
            arrow = (" \u25bc" if self.sort_rev else " \u25b2") if key == self.sort_col else ""
            self.tree.heading(key, text=text + arrow)

    def _row(self, u):
        return {**u, "status": "Inactive" if u["user_id"] in self.inactive else "Active"}

    def refresh_view(self):
        rows = [self._row(u) for u in self.users]
        q = self.v_search.get().strip().lower()
        if q:
            rows = [r for r in rows if any(q in str(r[k]).lower()
                                           for k in ("uid", "user_id", "name", "card", "role", "group"))]
        if self.v_status.get() != "All":
            rows = [r for r in rows if r["status"] == self.v_status.get()]
        if self.v_role.get() != "All":
            rows = [r for r in rows if r["role"] == self.v_role.get()]
        rows.sort(key=lambda r: sort_key(r[self.sort_col]), reverse=self.sort_rev)

        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", iid=str(r["uid"]),
                             values=[r[c[0]] for c in COLUMNS],
                             tags=("inactive",) if r["status"] == "Inactive" else ())
        still = [i for i in selected if self.tree.exists(i)]
        if still:
            self.tree.selection_set(still)
        n_inactive = sum(1 for u in self.users if u["user_id"] in self.inactive)
        self.lbl_count.config(text=f"Showing {len(rows)} of {len(self.users)} users "
                                   f"({n_inactive} inactive)")
        roles = ["All"] + sorted({u["role"] for u in self.users})
        self.cb_role.config(values=roles)

    # ---- activate / deactivate -------------------------------------------- #
    def set_active(self, active):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select one or more users first.")
            return
        by_uid = {str(u["uid"]): u for u in self.users}
        ids = [by_uid[i]["user_id"] for i in sel if i in by_uid]
        if not active and not messagebox.askyesno(
                "Deactivate", f"Deactivate {len(ids)} user(s) in your system?"):
            return
        for uid in ids:
            (self.inactive.discard if active else self.inactive.add)(uid)
        save_state(self._cfg_snapshot(), self.inactive)
        self.refresh_view()

    # ---- worker messages / status line ------------------------------------ #
    def _poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "users":
                    self.users, self.last_sync = msg[1], msg[2]
                    self.conn_state, self.last_error = "online", ""
                    self.refresh_view()
                elif msg[0] == "offline":
                    self.conn_state = "offline"
                elif msg[0] == "error":
                    self.conn_state, self.last_error = "error", msg[1]
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _tick(self):
        cfg = self._cfg_snapshot()
        target = f"{cfg['ip']}:{cfg['port']}"
        synced = time.strftime("%H:%M:%S", time.localtime(self.last_sync)) if self.last_sync else None
        if self.conn_state == "online" and self.last_sync:
            left = max(0, int(cfg["cache_seconds"] - (time.time() - self.last_sync)))
            text = f"\u25cf Synced {synced}  |  next device read in {left}s  |  {target}"
        elif self.conn_state == "offline":
            cached = f"showing cached data from {synced}" if synced else "no data yet"
            text = f"\u25cb Device offline - {cached} - waiting for {target} to come back"
        elif self.conn_state == "error":
            text = f"\u25cb Device reachable but read failed: {self.last_error} - retrying"
        else:
            text = f"Waiting for first connection to {target} ..."
        self.lbl_conn.config(text=text)
        self.after(1000, self._tick)


if __name__ == "__main__":
    App().mainloop()

# NOTE on Activate/Deactivate
#   The ZK protocol has no standard "disabled" flag on a user record, so the flag is kept in
#   YOUR system (identix_state.json). That controls what your software shows / counts / allows.
#   If you need the device itself to refuse a deactivated member at the door, the options are:
#   (a) delete the user from the device (CMD_DELETE_USER = 18) and re-enroll later - this loses
#       the fingerprints unless you back them up first, or
#   (b) move them to a device group with no access time-zone. Both are device/firmware specific,
#   so test on one throw-away user before automating either.

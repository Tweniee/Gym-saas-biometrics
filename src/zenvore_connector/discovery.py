from __future__ import annotations
import ipaddress
import socket
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait
from .adapters import AdapterError



def windows_ethernet_names():
    """Use the OS adapter type (Ethernet=6), not an arbitrary interface name."""
    import json
    import subprocess
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); Get-NetAdapter -Physical -ErrorAction Stop | Select-Object Name,InterfaceType | ConvertTo-Json -Compress"],
            capture_output=True, timeout=5, check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        rows = json.loads(result.stdout.decode("utf-8-sig") or "[]")
        if isinstance(rows, dict):
            rows = [rows]
        return {row["Name"] for row in rows if row.get("InterfaceType") == 6}
    except (OSError, ValueError, subprocess.SubprocessError):
        # Unknown type is never permission to automatically scan.
        return set()


def macos_ethernet_names():
    """Map en* devices by macOS hardware-port type; Wi-Fi en0 is not Ethernet."""
    import subprocess
    try:
        result = subprocess.run(["/usr/sbin/networksetup", "-listallhardwareports"],
                                capture_output=True, timeout=5, check=True)
        selected = set()
        port = ""
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("Hardware Port: "):
                port = line.partition(": ")[2].lower()
            elif line.startswith("Device: "):
                if ("ethernet" in port or " lan" in port or port == "lan") and not any(
                        value in port for value in ("wi-fi", "wifi", "wireless")):
                    selected.add(line.partition(": ")[2].strip())
        return selected
    except (OSError, subprocess.SubprocessError):
        return set()

def interfaces():
    """Offer actual active interfaces; do not silently scan a guessed /24."""
    import psutil
    found = []
    ethernet = (windows_ethernet_names() if os.name == "nt" else
                macos_ethernet_names() if sys.platform == "darwin" else None)
    stats = psutil.net_if_stats()
    for name, addresses in psutil.net_if_addrs().items():
        if not stats.get(name) or not stats[name].isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            ip = ipaddress.ip_address(address.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            virtual = any(part in name.lower() for part in ("vpn", "tun", "tap", "utun", "veth", "docker", "vmnet", "virtual", "tailscale"))
            found.append({"name": name, "address": str(ip), "subnet": str(ipaddress.ip_network(str(ip) + '/' + address.netmask, strict=False)), "selectedByDefault": not virtual and (name in ethernet if ethernet is not None else not any(p in name.lower() for p in ("wi-fi", "wifi", "wlan", "wireless")))})
    return found


def bounded_discover(subnets, ports, handshake, timeout=0.6):
    """Only adapter-registered protocols may provide handshake(ip,port,timeout).

    A successful non-destructive protocol handshake must return stable identity
    and capabilities. A socket connect result is never accepted as identity.
    """
    hosts = set()
    for subnet in subnets:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version != 4 or network.prefixlen < 24 or not network.is_private:
            raise ValueError("Select a private IPv4 subnet of /24 or smaller")
        hosts.update(str(ip) for ip in network.hosts())
        if len(hosts) > 256:
            raise ValueError("Discovery is limited to 256 hosts")
    ports = sorted(set(ports))
    if not 1 <= len(ports) <= 4 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Select at most four documented adapter ports")
    if not 0 < timeout <= 1:
        raise ValueError("Discovery timeout must be at most one second")
    def probe(ip, port):
        try:
            candidate = handshake(ip, port, timeout)
            if isinstance(candidate, dict) and isinstance(candidate.get("identity"), str) and candidate["identity"]:
                return {**candidate, "ip": ip, "port": port}
        except (AdapterError, OSError, ValueError):
            return None
        return None
    pool = ThreadPoolExecutor(max_workers=16)
    futures = [pool.submit(probe, ip, port) for ip in sorted(hosts) for port in ports]
    done, pending = wait(futures, timeout=12)
    for future in pending:
        future.cancel()
    pool.shutdown(wait=False, cancel_futures=True)
    return [candidate for future in done if (candidate := future.result())][:32]


def simulator_candidates(config, store):
    if not config.development or not config.simulator_file:
        raise AdapterError("UNSUPPORTED")
    import json
    from .adapters.simulator import Simulator
    if config.simulator_file.stat().st_size > 2 * 1024 * 1024:
        raise AdapterError("INVALID_DEVICE_DATA")
    ports = list(json.loads(config.simulator_file.read_text(encoding="utf-8"))["devices"])
    if len(ports) > 16:
        raise AdapterError("INVALID_DEVICE_DATA")
    candidates = []
    for port in ports:
        device = {"ip": "127.0.0.1", "port": int(port)}
        try:
            identity = Simulator(device, config.simulator_file, store).health()
            candidates.append({"identity": identity, "adapter": "simulator", **device})
        except AdapterError:
            continue
    return candidates

def ethernet_candidates(config, store, selected=None):
    """Scan only active Ethernet selections, using the computer's /24 at most."""
    from .adapters.zk_protocol import Protocol
    from .auth import CredentialStore
    choices = selected if selected is not None else [i for i in interfaces() if i["selectedByDefault"]]
    subnets = []
    for item in choices:
        network = ipaddress.ip_network(item["subnet"])
        if network.prefixlen < 24:
            network = ipaddress.ip_network(item["address"] + "/24", strict=False)
        if network.is_private:
            subnets.append(str(network))
    if not subnets:
        return []
    # One network per scan avoids a surprise broad search on multi-NIC hosts.
    secrets = CredentialStore(config.state_dir, config.development, "devices.credential").load() or {}
    def handshake(ip, port, timeout):
        from .sync import ProcessDeviceLock
        lock = ProcessDeviceLock(config.state_dir, "endpoint:" + ip + ":" + str(port))
        if not lock.acquire(blocking=False):
            return None
        try:
            with Protocol(ip, port, secrets.get(ip + ":" + str(port), 0), timeout).connected() as session:
                identity = session.serial()
                session.counts()
                return {"identity": identity, "adapter": "zk-tcp"}
        finally:
            lock.release()
    return bounded_discover(subnets[:1], [4370], handshake)

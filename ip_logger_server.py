#!/usr/bin/env python3
import os
import socket
import json
from pathlib import Path

from common_service import *

SERVICE_NAME = "IP_Logger"

def load_config():
    """
    Load ~/.config/ip_logger/config.json and return:
      trigger_host, namecheap_domain, namecheap_name, namecheap_key
    """
    home = Path(os.environ.get("HOME", str(Path.home())))
    cfg_path = home / ".config" / "ip_logger" / "config.json"

    if not cfg_path.exists():
        return None, None, None, None

    with cfg_path.open("r") as f:
        cfg = json.load(f)

    trigger_host = cfg.get("trigger_host")
    namecheap_key = cfg.get("namecheap_key")
    namecheap_domain = cfg.get("namecheap_domain")
    namecheap_name = cfg.get("namecheap_name")
    return trigger_host, namecheap_domain, namecheap_name, namecheap_key

def ip_to_str(ip: int) -> str:
    """Convert uint32_t ip (host order from server.c) to dotted string."""
    return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


def update_namecheap(namecheap_domain, namecheap_name, namecheap_key, ip_str):
    """
    Reproduce:
    curl "http://dynamicdns.park-your-domain.com/update?domain=...&host=...&password=...&ip=..." > /dev/null 2>&1
    """
    import subprocess
    url = (
        "http://dynamicdns.park-your-domain.com/update"
        f"?domain={namecheap_domain}"
        f"&host={namecheap_name}"
        f"&password={namecheap_key}"
        f"&ip={ip_str}"
    )
    print(f"[INFO] Namecheap update: {url}")
    try:
        subprocess.run(
            ["curl", url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception as e:
        print(f"[ERROR] Failed to run curl: {e}")


def main():
    print("[INFO] START")

    trigger_host, namecheap_domain, namecheap_name, namecheap_key = load_config()
    if trigger_host:
        print(f"[INFO] trigger_host = {trigger_host}")
    if namecheap_domain:
        print(f"[INFO] Namecheap domain = {namecheap_domain}")
    print("[INFO] INIT DONE")

    socket = service_register(SERVICE_NAME)
    if not socket:
        print("[ERROR] Cannot connect to zcure server")
        return 1

    # IP cache equivalent to static IP_Info _infos[100]
    infos: dict[str, int] = {}  # name -> last IP (uint32)

    while True:
        # Read Server2ServerApp_Header
        rsp = ServicePacket.receive(socket,
                                    [ CLIENT_CONNECT_NOTIFICATION, CLIENT_DISCONNECT_NOTIFICATION ])

        if rsp.op == CLIENT_DISCONNECT_NOTIFICATION:
            continue

        name = rsp.username
        ip = rsp.ip
        last_ip = infos.get(name, 0)
        if ip != last_ip:
            infos[name] = ip
            ip_str = ip_to_str(ip)
            print(f"[INFO] New IP for {name}: {ip_str}")

            if trigger_host and name == trigger_host:
                if namecheap_domain and namecheap_name and namecheap_key:
                    update_namecheap(namecheap_domain, namecheap_name, namecheap_key, ip_str)
                else:
                    print("[WARN] Namecheap config incomplete, not updating")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


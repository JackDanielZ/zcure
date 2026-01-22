#!/usr/bin/env python3
""" zcure IP logger client """

import sys
import socket
import struct
import secrets

from common_app import *

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} user@server:port", file=sys.stderr)
        return 1

    print("[INFO] zcure client test")
    sock, _ = zcure_client_connect(sys.argv[1], "IP_Logger")

    if sock == -1:
        print(f"[ERROR] Cannot establish secure connection to {sys.argv[1]}", file=sys.stderr)
        return 1

    print(f"[INFO] Success!")
    sock.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


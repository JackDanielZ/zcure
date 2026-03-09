#!/usr/bin/env python3
import select

from common_app import *

port = 9091
SERVICE_NAME = f"Port_Fwd_{port}"

debug = False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} user@server:port", file=sys.stderr)
        return 1

    local_master_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_master_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_master_sock.bind(('127.0.0.1', port))
    local_master_sock.listen(5)
    local_master_sock.setblocking(False)

    inputs = [ local_master_sock ]
    local_to_remote_socks = {}
    remote_to_local_socks = {}
    remote_to_keys = {}
    while True:
        readable, _, _ = select.select(inputs + list(local_to_remote_socks.keys()) + list(remote_to_local_socks.keys()), [], [])
        for sock in readable:
            if sock == local_master_sock:
                if debug == True: print("Connection from local")
                client_sock, _ = local_master_sock.accept()
                zcure_sock, shared_key = zcure_client_connect(sys.argv[1], SERVICE_NAME)
                if zcure_sock == -1:
                    print(f"[ERROR] Cannot establish secure connection to {sys.argv[1]}", file=sys.stderr)
                    client_sock.close()
                    continue
                local_to_remote_socks[client_sock] = zcure_sock
                remote_to_local_socks[zcure_sock] = client_sock
                remote_to_keys[zcure_sock] = shared_key
            elif sock in local_to_remote_socks:
                remote_sock = local_to_remote_socks[sock]
                data = sock.recv(1000000)
                if debug == True: print(f"Data from local: {len(data)} bytes, {data}")
                if len(data) == 0:
                    # Remove socket and CID from lists
                    del local_to_remote_socks[sock]
                    del remote_to_local_socks[remote_sock]
                    remote_sock.close()
                    sock.close()
                else:
                    # Send to service
                    pkt = AppData(data)
                    pkt.encrypt(remote_to_keys[remote_sock])
                    remote_sock.sendall(pkt.data_to_send)
            elif sock in remote_to_local_socks:
                pkt = AppData()
                pkt.receive(sock)
                pkt.decrypt(remote_to_keys[sock])
                if debug == True: print(f"Data from remote: {len(pkt.data)}, {pkt.data}")
                remote_to_local_socks[sock].sendall(pkt.data)

    return 0

    if cid == -1:
        print(f"[ERROR] Cannot establish secure connection to {sys.argv[1]}", file=sys.stderr)
        return 1

    print(f"[INFO] Success! CID assigned")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


#!/usr/bin/env python3
import select

from common_service import *

port = 9091
SERVICE_NAME = f"Port_Fwd_{port}"

debug = False

def main():
    print("[INFO] START")

    zcure_server_socket = service_register(SERVICE_NAME)
    if not zcure_server_socket:
        print("[ERROR] Cannot connect to zcure server")
        return 1

    inputs = [ zcure_server_socket ]
    cid_to_fd = {}
    fd_to_cid = {}
    exit_required = False
    while exit_required == False:
        try:
            readable, _, _ = select.select(inputs, [], [])
            for sock in readable:
                if sock == zcure_server_socket:
                    rsp = ServicePacket.receive(sock,
                                                [ CLIENT_CONNECT_NOTIFICATION, 
                                                  CLIENT_DISCONNECT_NOTIFICATION,
                                                  CLIENT_DATA ])
                    if rsp.op == CLIENT_CONNECT_NOTIFICATION:
                        # Connect to server, add fd to inputs and assign CID to fd
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect(("localhost", port))
                        inputs.append(sock)
                        cid_to_fd[rsp.app_id] = sock
                        fd_to_cid[sock] = rsp.app_id
                        if debug == True: print(f"New client {rsp.app_id}")
                    elif rsp.op == CLIENT_DISCONNECT_NOTIFICATION:
                        # close socket to server and remove from lists
                        inputs.remove(cid_to_fd[rsp.app_id])
                        cid_to_fd[rsp.app_id].close()
                        if debug == True: print(f"Remove client {rsp.app_id}")
                    elif rsp.op == CLIENT_DATA:
                        # Send data to server socket
                        cid_to_fd[rsp.app_id].sendall(rsp.data)
                        if debug == True: print(f"Send data ({len(rsp.data)} bytes) from client {rsp.app_id} to local server")
                else:
                    data = sock.recv(1000000)
                    app_id = fd_to_cid[sock]
                    if len(data) == 0:
                        # Remove socket and CID from lists
                        sock.close()
                        fd_to_cid.remove(sock)
                        cid_to_fd.remove(app_id)
                    else:
                        # Send to CID
                        req = ServiceClientData(app_id, data)
                        zcure_server_socket.sendall(req.serialize())
                        if debug == True: print(f"Send data ({len(data)} bytes) from local server to client {app_id}")
        except Exception as e:
            print(f"[ERROR] {e}")
            exit_required = True

    return 0

if __name__ == "__main__":
    raise SystemExit(main())


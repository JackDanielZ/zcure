#!/usr/bin/env python3
import os
import socket
import struct
import select
import json
import secrets
import traceback
from typing import Dict

from common_service import *
from common_app import *

debug = False

class ZcureServer:
    def __init__(self, port: str):
        self.port = port
        self.services: Dict[str, socket.socket] = {}
        self.clients: Dict[int, dict] = {}
        self.next_client_id = 0
        self.master_tcp_socket = self._create_tcp_socket(port)
        self.master_uds_socket = self._create_uds_socket()
        self.client_socks = []
        self.service_socks = []
        print(f"P-384 zcure server ready on port {port}")

    def _create_tcp_socket(self, port: str) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', int(port)))
        sock.listen(5)
        sock.setblocking(False)
        return sock

    def _create_uds_socket(self) -> socket.socket:
        path = "/tmp/zcureserver"
        try:
            os.unlink(path)
        except:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        sock.listen(5)
        sock.setblocking(False)
        return sock

    def _is_service_allowed(self, service: str, username: str) -> bool:
        perm_file = CONFIG_DIR / "permissions.json"
        if not perm_file.exists():
            return False
        with open(perm_file, "r", encoding="utf-8") as f:
            permissions = json.load(f)
            if service not in permissions:
                return False
            allowed = permissions[service]
            return ':all:' in allowed or username in allowed
        return False

    def handle_client_connect(self, client_sock: socket.socket, client_addr):
        try:
            req = AppConnectionRequest()
            req.receive(client_sock)

            # Decrypt service field
            shared_key = compute_shared_key(req.username, req.salt)

            req.decrypt(shared_key)
            print("App for service", req.service)

            if req.service not in self.services:
                print(f"No service {req.service}")
                status = 1
                session_key = bytes(32)
            elif not self._is_service_allowed(req.service, req.username):
                print(f"App {req.username} not allowed for service {req.service}")
                status = 2
                session_key = bytes(32)
            else:
                # Generate session key/IV
                status = 0
                session_key = secrets.token_bytes(32)

            rsp = AppConnectionResponse(status, session_key)
            rsp.encrypt(shared_key)
            client_sock.sendall(rsp.data_to_send)

            if status != 0:
                raise ValueError("Unknown required service or no permission for this user")

            # Store client
            self.clients[client_sock.fileno()] = {
                'client_sock': client_sock,
                'service_sock': self.services[req.service],
                'shared_key': session_key,
                'username': req.username
            }

            # Notify service about new client (simplified)
            client_ip = struct.unpack("<I", socket.inet_aton(client_addr[0]))[0]
            pkt = ServiceClientConnection(client_sock.fileno(), req.username, client_ip)
            self.services[req.service].sendall(pkt.serialize())
        except Exception as e:
            traceback.print_exc()
            print(f"[Error during client connection] {e}")
            client_sock.close()
            return False
        return True

    def handle_service_register(self, service_sock: socket.socket):
        try:
            req = ServicePacket.receive(service_sock, [ SERVICE_REGISTER_REQUEST ])
            if req.service in self.services:
                raise ValueError("Service already registered")
            rsp = ServiceConnectionResponse(0)
            service_sock.sendall(rsp.serialize())
            self.services[req.service] = service_sock
            print(f"Service '{req.service}' registered")
        except Exception as e:
            print(f"[Error during service registration] {e}")
            self.service_socks.remove(service_sock)
            service_sock.close()

    def handle_client_data(self, client_sock: socket.socket):
        try:
            client_info = self.clients[client_sock.fileno()]
            key = client_info['shared_key']
            service_sock = client_info['service_sock']
            req = AppData()
            req.receive(client_sock)
            req.decrypt(key)
        except Exception as e:
            print(f"[Error during data reception from client] {e}")
            pkt = ServiceClientDisconnection(client_sock.fileno())
            service_sock.sendall(pkt.serialize())
            del self.clients[client_sock.fileno()]
            self.client_socks.remove(client_sock)
            client_sock.close()
            return

        if debug == True: print(f"Sending data ({len(req.plaintext)}) from client {client_sock.fileno()}")
        try:
            pkt = ServiceClientData(client_sock.fileno(), req.plaintext)
            service_sock.sendall(pkt.serialize())
        except Exception as e:
            print(f"[Error during data sending from client to service] {e}")
            self.service_socks.remove(service_sock)
            service_sock.close()

    def handle_service_data(self, service_sock: socket.socket):
        try:
            svc_pkt = ServicePacket.receive(service_sock, [ CLIENT_DATA ])
        except Exception as e:
            print(f"[Error during data reception from service] {e}")
            self.services = {service: sock for service, sock in self.services.items() if sock is not service_sock}
            self.service_socks.remove(service_sock)
            service_sock.close()
            return

        if debug == True: print(f"Sending data ({len(svc_pkt.data)}) from service to client {svc_pkt.app_id}")
        client_sock = None
        try:
            client_info = self.clients[svc_pkt.app_id]
            if debug == True: print(client_info)
            client_sock = client_info['client_sock']
            shared_key = client_info['shared_key']
            app_pkt = AppData(svc_pkt.data)
            app_pkt.encrypt(shared_key)
            client_sock.sendall(app_pkt.data_to_send)
        except Exception as e:
            print(f"[Error during data sending from service to client] {e}")
            if client_sock != None and client_sock in self.clients:
                del self.clients[client_sock]
                client_sock.close()

    def run(self):
        inputs = [self.master_tcp_socket, self.master_uds_socket]
        while True:
            readable, _, _ = select.select(inputs + self.client_socks + self.service_socks, [], [])
            for sock in readable:
                if sock == self.master_tcp_socket:
                    if debug == True: print("External connection")
                    client_sock, client_addr = sock.accept()
                    if self.handle_client_connect(client_sock, client_addr):
                        self.client_socks.append(client_sock)
                elif sock == self.master_uds_socket:
                    if debug == True: print("Internal connection")
                    service_sock, _ = sock.accept()
                    self.handle_service_register(service_sock)
                    self.service_socks.append(service_sock)
                elif sock in self.client_socks:
                    if debug == True: print("Data from client")
                    self.handle_client_data(sock)
                elif sock in self.service_socks:
                    if debug == True: print("Data from service")
                    self.handle_service_data(sock)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3 or sys.argv[1] != '-p':
        print("Usage: python3 zcure_server.py -p PORT")
        sys.exit(1)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    server = ZcureServer(sys.argv[2])
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nzcure server stopped")


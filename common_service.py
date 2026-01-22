import socket
import struct

SERVICE_REGISTER_REQUEST       = 0
SERVICE_REGISTER_RESPONSE      = 1
CLIENT_DATA                    = 2
CLIENT_CONNECT_NOTIFICATION    = 3
CLIENT_DISCONNECT_NOTIFICATION = 4

SERVICE_PACKET_FORMAT = "III" # size, op, app_id

class ServicePacket:
    def __init__(self, op, app_id = 0xFFFFFFFF):
        self.op = op
        self.app_id = app_id

    @staticmethod
    def receive(sock: socket.socket, expected_ops: list):
        size = struct.calcsize(SERVICE_PACKET_FORMAT)
        data = bytes()

        while len(data) < size:
            recv_data = sock.recv(size - len(data))
            if len(recv_data) == 0:
                sock.close()
                raise ValueError("Connection closed")
            data += recv_data

        pkt_size, op, app_id = struct.unpack(SERVICE_PACKET_FORMAT, data)
        if op not in expected_ops:
            raise ValueError(f"Wrong packet type {op}")
        if op == SERVICE_REGISTER_REQUEST:
            inst = ServiceConnectionRequest()
        elif op == SERVICE_REGISTER_RESPONSE:
            inst = ServiceConnectionResponse()
        elif op == CLIENT_CONNECT_NOTIFICATION:
            inst = ServiceClientConnection()
        elif op == CLIENT_DATA:
            inst = ServiceClientData()
        elif op == CLIENT_DISCONNECT_NOTIFICATION:
            inst = ServiceClientDisconnection()
        else:
            raise ValueError(f"Wrong op {op}, cannot instantiate")
        while len(data) < pkt_size:
            recv_data = sock.recv(pkt_size - len(data))
            if len(recv_data) == 0:
                sock.close()
                raise ValueError("Connection closed")
            data += recv_data
        inst.data = data
        if len(data) != pkt_size:
            raise ValueError("Wrong packet size")
        inst.deserialize()
        return inst

    def deserialize(self):
        self.pkt_size, self.op, self.app_id = struct.unpack_from(SERVICE_PACKET_FORMAT, self.data, 0)

    def serialize(self):
        return struct.pack(SERVICE_PACKET_FORMAT, self.calcsize(), self.op, self.app_id)

    def calcsize(self):
        return struct.calcsize(SERVICE_PACKET_FORMAT)

class ServiceConnectionRequest(ServicePacket):
    def __init__(self, service: str = None):
        super().__init__(op = SERVICE_REGISTER_REQUEST)
        self.__fmt = "32s"
        self.service = service

    def deserialize(self):
        super().deserialize()
        offset = super().calcsize()
        self.service, = struct.unpack_from(self.__fmt, self.data, offset)
        self.service = self.service.rstrip(b'\x00').decode()

    def serialize(self):
        return super().serialize() + struct.pack(self.__fmt, self.service.encode())

    def calcsize(self):
        return super().calcsize() + struct.calcsize(self.__fmt)

class ServiceConnectionResponse(ServicePacket):
    def __init__(self, status: int = -1):
        super().__init__(op = SERVICE_REGISTER_RESPONSE)
        self.__fmt = "B"
        self.status = status

    def deserialize(self):
        super().deserialize()
        offset = super().calcsize()
        self.status, = struct.unpack_from(self.__fmt, self.data, offset)

    def serialize(self):
        return super().serialize() + struct.pack(self.__fmt, self.status)

    def calcsize(self):
        return super().calcsize() + struct.calcsize(self.__fmt)

class ServiceClientConnection(ServicePacket):
    def __init__(self, app_id: int = 0xFFFFFFFF, username: str = None, ip: int = -1):
        super().__init__(op = CLIENT_CONNECT_NOTIFICATION, app_id = app_id)
        self.__fmt = "32sI"
        self.username = username
        self.ip = ip

    def deserialize(self):
        super().deserialize()
        offset = super().calcsize()
        self.username, self.ip = struct.unpack_from(self.__fmt, self.data, offset)
        self.username = self.username.rstrip(b'\x00').decode()

    def serialize(self):
        return super().serialize() + struct.pack(self.__fmt, self.username.encode(), self.ip)

    def calcsize(self):
        return super().calcsize() + struct.calcsize(self.__fmt)

class ServiceClientDisconnection(ServicePacket):
    def __init__(self, app_id: int = 0xFFFFFFFF):
        super().__init__(op = CLIENT_DISCONNECT_NOTIFICATION, app_id = app_id)

class ServiceClientData(ServicePacket):
    def __init__(self, app_id: int = 0xFFFFFFFF, data: bytes() = None):
        super().__init__(op = CLIENT_DATA, app_id = app_id)
        if data != None:
            self.__fmt = f"{len(data)}s"
        self.data = data

    def deserialize(self):
        super().deserialize()
        offset = super().calcsize()
        self.data, = struct.unpack_from(f"{self.pkt_size - offset}s", self.data, offset)

    def serialize(self):
        return super().serialize() + struct.pack(self.__fmt, self.data)

    def calcsize(self):
        return super().calcsize() + struct.calcsize(self.__fmt)


ZCURE_SOCKET = "/tmp/zcureserver"   # local UNIX socket used by server

def service_register(service_name: str) -> socket.socket:
    """
    Python equivalent of zcure_server_register("IP_Logger") in server_app.c:
    - Connect to /tmp/zcureserver
    - Send ServerConnectionRequest { char service[32]; int status; }
    - Wait for int status from server
    - Return connected socket on success
    """
    # Connect to local UNIX socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(ZCURE_SOCKET)
    except ConnectionRefusedError as e:
        print(f"[ERROR] Cannot connect to zcure local socket: {e}")
        return None

    # Build and send request to server
    try:
        req = ServiceConnectionRequest(service_name)
        sock.sendall(req.serialize())
    except ValueError as e:
        print(f"[ERROR] Failed to send service registration: {e}")
        sock.close()
        return None

    # Receive int status from server: 0 = OK, !=0 error (matches main.c)[file:14]
    try:
        rsp = ServicePacket.receive(sock, [ SERVICE_REGISTER_RESPONSE ])
    except ValueError as e:
        print(f"[ERROR] Failed to receive registration status: {e}")
        sock.close()
        return None

    if rsp.status != 0:
        print(f"[ERROR] Registration for service '{service_name}' failed, status={status}")
        sock.close()
        return None

    print(f"[INFO] Service '{service_name}' registered with zcure")
    return sock


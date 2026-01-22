import sys
import struct
import socket
import secrets
import json
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key

IV_SIZE = 12
TAG_SIZE = 16

USERNAME_SIZE = 32
SERVICE_SIZE = 32
SALT_SIZE = 128
SESSION_KEY_SIZE = 32

CONFIG_DIR = Path.home() / ".config" / "zcure"
KEYS_FILE = CONFIG_DIR / "keys.json"

def load_local_privkey384(keys):
    priv = int(keys["local"]["p"], 16)
    return derive_private_key(private_value=priv, curve=ec.SECP384R1())

def load_remote_pubkey384(keys, username: str) -> ec.EllipticCurvePublicKey:
    pub_x_hex = keys["remote"][username]["x"]
    pub_y_hex = keys["remote"][username]["y"]
    x = int(pub_x_hex, 16)
    y = int(pub_y_hex, 16)
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1())
    return public_numbers.public_key()

def compute_shared_key(username: str, salt: bytes) -> bytes:
    """P-384 HKDF(SHA384(ECDH + salt))."""
    filename = KEYS_FILE
    if not filename.exists():
        raise FileNotFoundError(f"Local key missing: {filename}")

    with open(KEYS_FILE, "r", encoding="utf-8") as f:
        keys = json.load(f)
        local_priv = load_local_privkey384(keys)
        peer_pub = load_remote_pubkey384(keys, username)

    shared_secret = local_priv.exchange(ec.ECDH(), peer_pub)
    input_data = shared_secret + salt
    hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b'', backend=None)
    return hkdf.derive(input_data)

def aesgcm_encrypt(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(iv, plaintext, aad)
    return encrypted[:-16], encrypted[-16:]  # ct, tag

def aesgcm_decrypt(key: bytes, iv: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct + tag, aad)

def parse_target(target: str) -> tuple[str, str, int]:
    """Parse user@server:port → (user, server, port)"""
    if '@' not in target or ':' not in target:
        raise ValueError(f"Expected user@server:port, got {target}")
    user, hostport = target.split('@', 1)
    if ':' not in hostport:
        raise ValueError(f"Expected server:port, got {hostport}")
    server, port_str = hostport.rsplit(':', 1)
    port = int(port_str)
    return user, server, port

def zcure_client_connect(target: str, service: str) -> int:
    """zcure_client_connect() equivalent - returns CID or -1"""
    user, server, port = parse_target(target)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))

    # Generate salt
    salt = secrets.token_bytes(SALT_SIZE)

    # Compute shared key
    shared_key = compute_shared_key(server, salt)

    # Encrypt request
    req = AppConnectionRequest(user, service, salt)
    req.encrypt(shared_key)
    sock.sendall(req.data_to_send)

    rsp = AppConnectionResponse()
    rsp.receive(sock)
    rsp.decrypt(shared_key)

    if rsp.status != 0:
        print(f"[ERROR] Server rejected connection, status={rsp.status}")
        sock.close()
        return -1, None

    return sock, rsp.session_key

class AppPacket:
    def __init__(self):
        self.aad_fmt = None
        self.text_fmt = None
        self.max_text_size = -1
        self.aad = bytes()

    def encrypt(self, key: bytes):
        iv = secrets.token_bytes(IV_SIZE)
        pkt_size = 4 + (struct.calcsize(self.aad_fmt) if self.aad_fmt else 0) + IV_SIZE + len(self.plaintext) + TAG_SIZE
        self.aad = struct.pack("<I", pkt_size) + self.aad
        ct, tag = aesgcm_encrypt(key, iv, self.aad, self.plaintext)
        self.data_to_send = self.aad + ct + iv + tag

    def decrypt(self, key: bytes):
        self.plaintext = aesgcm_decrypt(key, self.iv, self.aad, self.ciphertext, self.tag)
        self.unpack_text()

    def receive(self, sock: socket.socket):
        if self.aad_fmt != None:
            aad_size = struct.calcsize(self.aad_fmt)
        else:
            aad_size = 0
        if self.text_fmt != None:
            text_size = struct.calcsize(self.text_fmt)
        else:
            if self.max_text_size == -1:
                raise ValueError("AppPacket text size cannot be determined")
            text_size = self.max_text_size

        data = sock.recv(4) # Retrieve pkt size
        if len(data) == 0:
            raise ValueError("Connection closed")
        self.pkt_size, = struct.unpack("<I", data)

        if self.max_text_size == -1 and text_size != (self.pkt_size - 4 - aad_size - IV_SIZE - TAG_SIZE):
            raise ValueError(f"AppPacket incorrect received text - {text_size = }, {self.pkt_size - 4 - aad_size - IV_SIZE - TAG_SIZE = }")
        if self.pkt_size < 4 + IV_SIZE + TAG_SIZE:
            raise ValueError(f"AppPacket insufficient received mandatory ({len(data)})")

        while len(data) < self.pkt_size:
            recv_data = sock.recv(self.pkt_size - len(data))
            if len(recv_data) == 0:
                raise ValueError("Connection closed")
            data += recv_data

        recv_text_size = len(data) - 4 - aad_size - IV_SIZE - TAG_SIZE
        self.aad = data[:4 + aad_size]
        self.ciphertext = data[-recv_text_size-IV_SIZE-TAG_SIZE:-IV_SIZE-TAG_SIZE]
        self.iv = data[-IV_SIZE-TAG_SIZE:-TAG_SIZE]
        self.tag = data[-TAG_SIZE:]
        if self.aad_fmt != None:
            self.unpack_aad(self.aad[4:])
        if self.text_fmt == None:
            self.text_fmt = f"{recv_text_size}s"

    def unpack_aad(self, aad):
        pass

    def unpack_text(self):
        pass

class AppData(AppPacket):
    def __init__(self, data: bytes = None):
        super().__init__()
        self.data = None
        if data != None:
            self.text_fmt = f"{len(data)}s"
            self.plaintext = struct.pack(self.text_fmt, data)
        else:
            self.max_text_size = 1000000

    def unpack_text(self):
        self.data, = struct.unpack(self.text_fmt, self.plaintext)

class AppConnectionRequest(AppPacket):
    def __init__(self, username: str = None, service: str = None, salt: bytes = None):
        super().__init__()
        self.aad_fmt = f"{USERNAME_SIZE}s{SALT_SIZE}s"
        self.text_fmt = f"{SERVICE_SIZE}s"
        self.username = None
        self.salt = None
        if username != None or service != None or salt != None:
            if username == None:
                raise ValueError(f"Username must be provided")
            if service == None:
                raise ValueError(f"Username must be provided")
            if salt == None or len(salt) != SALT_SIZE:
                raise ValueError(f"Salt must be provided and of {SALT_SIZE} bytes")
            self.aad = struct.pack(self.aad_fmt, username.encode(), salt)
            self.plaintext = struct.pack(self.text_fmt, service.encode())

    def unpack_aad(self, aad):
        self.username, self.salt = struct.unpack(self.aad_fmt, aad)
        self.username = self.username.rstrip(b'\x00').decode()

    def unpack_text(self):
        self.service, = struct.unpack(self.text_fmt, self.plaintext)
        self.service = self.service.rstrip(b'\x00').decode()

class AppConnectionResponse(AppPacket):
    def __init__(self, status: int = -1, session_key: bytes = None):
        super().__init__()
        self.aad_fmt = None
        self.aad = bytes()
        self.text_fmt = f"B{SESSION_KEY_SIZE}s"
        if session_key != None or status != -1:
            if len(session_key) != SESSION_KEY_SIZE:
                raise ValueError(f"Session key must be provided and of {SESSION_KEY_SIZE} bytes")
            self.plaintext = struct.pack(self.text_fmt, status, session_key)

    def unpack_text(self):
        self.status, self.session_key = struct.unpack(self.text_fmt, self.plaintext)

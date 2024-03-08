# clientsocket.py

import socket
import secrets
import hmac

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030  # The port used by the server
KEY = b"IN$3GU$/s3k-t34m-n1n3t3en"
SEP = b"|||"

def generate_nonce():
    return secrets.token_bytes(32)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    nonce = generate_nonce()
    message = b"Hello, world"
    hash = hmac.new(KEY, nonce + SEP + message, "sha3_256").digest()
    s.sendall(nonce + SEP + message + SEP + hash)


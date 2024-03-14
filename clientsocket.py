# clientsocket.py

import socket
import secrets
import hmac
import time

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030  # The port used by the server
KEY = b"IN$3GU$/s3k-t34m-n1n3t3en"
SEP = b"|||"


def generate_nonce(sim_same_nonce=False):
    if sim_same_nonce:
        return b"0" * 32
    timestamp = int.to_bytes(int(time.time()), 8, "big")
    random = secrets.token_bytes(24)
    return timestamp + random


sim_same_nonce = input("Simulate same nonce? (y/n): ").strip().lower() == "y"
sim_mitm = input("Simulate MITM attack? (y/n): ").strip().lower() == "y"
message = bytes(input("Press Enter to send a message: "), "utf-8")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    nonce = generate_nonce(sim_same_nonce)
    hash = hmac.new(KEY, nonce + SEP + message, "sha3_256").digest()
    if sim_mitm:
        message = b"Hello, i'm a MITM!"
    s.sendall(nonce + SEP + message + SEP + hash)

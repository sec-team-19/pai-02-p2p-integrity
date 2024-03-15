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
    # testing purposes only delete this in production
    if sim_same_nonce:
        return b"0" * 32
    # -----------------------------------------------

    timestamp = int.to_bytes(int(time.time()), 8, "big")
    random = secrets.token_bytes(24)
    return timestamp + random


# testing purposes only delete this in production
sim_same_nonce = input("Simulate same nonce? (y/n): ").strip().lower() == "y"
if sim_same_nonce:
    print("Send another message with same nonce to simulate a reply attack.")
sim_mitm = input("Simulate MITM attack? (y/n): ").strip().lower() == "y"
# -----------------------------------------------
acc_origin = input("Account origin: ").strip()
acc_dest = input("Account destination: ").strip()
amount = input("Amount: ").strip()

message = f"{acc_origin}, {acc_dest}, {amount}"
message = bytes(message, "utf-8")

if not acc_origin or not acc_dest or not amount:
    print("You must inform all fields")
    exit(1)

if not acc_origin.isdigit() or not acc_dest.isdigit() or not amount.isdigit():
    print("Invalid input")
    exit(1)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    nonce = generate_nonce(sim_same_nonce)
    hash = hmac.new(KEY, nonce + SEP + message, "sha3_256").digest()
    # testing purposes only delete this in production
    if sim_mitm:
        message = b"Hello, i'm a MITM!"
    # -----------------------------------------------
    s.sendall(nonce + SEP + message + SEP + hash)

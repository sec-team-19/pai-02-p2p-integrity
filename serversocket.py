# serversocket.py

import socket
import sqlite3
import hmac

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)
KEY = b"IN$3GU$/s3k-t34m-n1n3t3en"
DB = "pai-02-p2p-integrity.db"
SEP = b"|||"

# create a database connection

conn = sqlite3.connect(DB)
c = conn.cursor()
c.execute(
    """
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY NOT NULL,
        message TEXT NOT NULL
    )
    """
)

def insert_message(id, message):
    c.execute("INSERT INTO messages (id, message) VALUES (?, ?)", (id, message))
    conn.commit()

def check_id_exists(id):
    c.execute("SELECT * FROM messages WHERE id=?", (id,))
    return c.fetchone() is not None

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            data_list = data.split(SEP)
            if len(data_list) != 3:
                print("Invalid data received")
                break
            nonce = data_list[0]
            message = data_list[1]
            hash_rec = data_list[2]
            hash = hmac.new(KEY, nonce + SEP + message, "sha3_256").digest()
            if hash != hash_rec:
                print("Hashes do not match")
                break
            if not data:
                break

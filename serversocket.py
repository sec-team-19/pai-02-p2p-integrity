# serversocket.py

import datetime
import socket
import sqlite3
import hmac

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)
KEY = b"IN$3GU$/s3k-t34m-n1n3t3en"
DB = "pai-02-p2p-integrity.db"
SEP = b"|||"
LOG_FILE = "compromised_messages.log"

# create a database connection

conn = sqlite3.connect(DB)
c = conn.cursor()
c.execute(
    """
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY NOT NULL,
        message TEXT NOT NULL,
        hash TEXT NOT NULL,
        is_mod INTEGER DEFAULT 0,
        rep_attempt INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
    )
    """
)
conn.close()

def log_compromised_message(id, message):
    with open(LOG_FILE, "a") as file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp}: Message ID {id} compromised - Message: {message}\n")


def insert_message(id, message, hash):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO messages (id, message, hash) VALUES (?, ?, ?)", (id, message, hash))
    conn.commit()
    c.close()
    conn.close()


def check_id_exists(id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM messages WHERE id=?", (id,))
    result = c.fetchone() is not None
    c.close()
    conn.close()
    return result

def update_rep_attempt(id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE messages SET rep_attempt = rep_attempt + 1 WHERE id = ?", (id,))
    conn.commit()
    c.close()
    conn.close()

def insert_mod_attempt(id, message, hash):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO messages (id, message, hash, is_mod) VALUES (?, ?, ?, 1)", (id, message, hash))
    conn.commit()
    c.close()
    conn.close()

def calculate_kpi():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total_messages = c.execute("SELECT COUNT(*) FROM messages WHERE is_mod < 1").fetchone()[0]
    total_replicated_attempts = c.execute("SELECT SUM(rep_attempt) FROM messages").fetchone()[0]
    total_modified_attempts = c.execute("SELECT COUNT(*) FROM messages WHERE is_mod > 0").fetchone()[0]
    c.close()
    conn.close()
    return total_messages, total_modified_attempts, total_replicated_attempts

def report_kpi():
    total_messages, total_modified_attempts, total_replicated_attempts = calculate_kpi()
    print("Total modification attempts:", total_modified_attempts)
    print("Total replication attempts:", total_replicated_attempts)
    print("Total messages received:", total_messages)
    integration_ratio = total_messages / (total_messages + total_modified_attempts + total_replicated_attempts)
    print("INTEGRATION RATIO:", round(integration_ratio, 3))


print("Server is running and listening for incoming connections in port", PORT)

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(2048)
            data_list = data.split(SEP)
            if len(data_list) != 3:
                print("Invalid data received")
                
            nonce = data_list[0]
            message = data_list[1]
            hash_rec = data_list[2]
            hash = hmac.new(KEY, nonce + SEP + message, "sha3_256").digest()
            if check_id_exists(nonce):
                update_rep_attempt(nonce)
                log_compromised_message(nonce, message.decode("utf-8"))
                print("Message already received, discarding message")
            else:
                if hash != hash_rec:
                    insert_mod_attempt(nonce, message, hash_rec)
                    log_compromised_message(nonce, message.decode("utf-8"))
                    print("Hashes do not match, message integrity compromised")
                else:
                    if not message:
                        print("No data received")
                    else:
                        print("Received", message.decode("utf-8"))
                        insert_message(nonce, message, hash_rec)
            report_kpi()

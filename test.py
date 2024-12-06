import socket
import threading
from select import select
import hashlib
import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

MAX_LEN = 200
NUM_COLORS = 6
clients = []
colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
seed = 0
clients_lock = threading.Lock()
USER_DB_FILE = "users.json"
CHAT_HISTORY_DIR = "chat_histories"  # Directory to store chat history files

# Ensure chat history directory exists
os.makedirs(CHAT_HISTORY_DIR, exist_ok=True)

# AES encryption parameters
AES_KEY = b'This is a key123'  # Use a secure key
AES_IV = os.urandom(16)  # Secure random IV

# Load user data from JSON file
def load_users():
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as file:
            return json.load(file)
    return {}

# Save user data to JSON file
def save_users(users_db):
    with open(USER_DB_FILE, 'w') as file:
        json.dump(users_db, file)

# Initialize the user database
users_db = load_users()

def color(code):
    return colors[code % NUM_COLORS]

# AES Encryption and Decryption Functions
def encrypt_message(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return base64.b64encode(AES_IV + encrypted_message).decode()

def decrypt_message(encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

# Save message to a unique encrypted chat history file for each user pair
def save_user_chat_history(sender, recipient, message):
    filename = f"{CHAT_HISTORY_DIR}/{sorted([sender, recipient])[0]}_{sorted([sender, recipient])[1]}_chat.txt"
    encrypted_message = encrypt_message(f"{sender}: {message}")
    with open(filename, "a") as file:
        file.write(encrypted_message + "\n")

# Retrieve chat history between two users
def retrieve_chat_history(user1, user2):
    filename = f"{CHAT_HISTORY_DIR}/{sorted([user1, user2])[0]}_{sorted([user1, user2])[1]}_chat.txt"
    if not os.path.exists(filename):
        return "No chat history found."
    decrypted_history = []
    with open(filename, "r") as file:
        for line in file:
            decrypted_message = decrypt_message(line.strip())
            decrypted_history.append(decrypted_message)
    return "\n".join(decrypted_history)

# Generate SHA-256 hash with a salt
def hash_password_sha256(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

# Authenticate or register a user
def authenticate_or_register_user(client_socket):
    try:
        credentials = client_socket.recv(MAX_LEN).decode()
        credentials = json.loads(credentials)

        username = credentials.get("username")
        password = credentials.get("password")
        action = credentials.get("action")

        if action == "login":
            if username in users_db:
                stored_salt, stored_hash = users_db[username].split('$')
                if hash_password_sha256(password, stored_salt) == stored_hash:
                    client_socket.sendall("LOGIN_SUCCESS".encode())
                    return username
            client_socket.sendall("LOGIN_FAILED".encode())
            return None
        elif action == "register":
            if username in users_db:
                client_socket.sendall("REGISTER_FAILED".encode())
                return None
            else:
                salt = secrets.token_hex(16)
                password_hash = hash_password_sha256(password, salt)
                users_db[username] = f"{salt}${password_hash}"
                save_users(users_db)
                client_socket.sendall("REGISTER_SUCCESS".encode())
                return username
    except Exception as e:
        print(f"Error in authenticate_or_register_user: {e}")
        client_socket.sendall("ERROR".encode())
        return None

# Broadcast message and save to individual chat histories
def broadcast_message(message, sender_id):
    sender_name = next(client['name'] for client in clients if client['id'] == sender_id)
    with clients_lock:
        for client in clients:
            if client['id'] != sender_id:
                try:
                    recipient_name = client['name']
                    client['socket'].sendall(f"{sender_name}: {message}".encode())
                    save_user_chat_history(sender_name, recipient_name, message)
                except OSError:
                    continue

# Send existing chat history to both users if they start chatting again
def send_existing_chat_history(user1, user2):
    chat_history = retrieve_chat_history(user1, user2)
    if chat_history != "No chat history found.":
        for client in clients:
            if client['name'] == user1 or client['name'] == user2:
                client['socket'].sendall(f"\n=== Previous Chat History between {user1} and {user2} ===\n".encode())
                client['socket'].sendall(chat_history.encode())
                client['socket'].sendall("\n=== End of Previous Chat History ===\n".encode())

def handle_client(client_socket, client_address, client_id):
    global clients
    name = None
    try:
        # Authenticate or register the user
        name = authenticate_or_register_user(client_socket)
        if not name:
            client_socket.close()
            return

        client_color = color(client_id)

        with clients_lock:
            clients.append({'id': client_id, 'name': name, 'socket': client_socket, 'color': client_color})

        # Check for previous chat history and send to both users
        for client in clients:
            if client['name'] != name:
                send_existing_chat_history(name, client['name'])

        welcome_message = f"{name} has joined"
        broadcast_message(welcome_message, client_id)
        print(client_color + welcome_message + "\033[0m")

        try:
            while True:
                ready, _, _ = select([client_socket], [], [], 0.1)
                if ready:
                    message = client_socket.recv(MAX_LEN).decode()
                    if message.startswith("#history"):
                        target_user = message.split(" ")[1]
                        chat_history = retrieve_chat_history(name, target_user)
                        client_socket.sendall(chat_history.encode())
                    elif not message or message == "#exit":
                        """break"""
                    else:
                        broadcast_message(message, sender_id=client_id)
                        print(client_color + f"{name}: {message}" + "\033[0m")
        except Exception as e:
            print(f"Error handling client {name}: {e}")
    finally:
        if name:
            with clients_lock:
                clients = [c for c in clients if c['id'] != client_id]
            client_socket.close()
            leave_message = f"{name} has left"
            broadcast_message(leave_message, client_id)
            print(client_color + leave_message + "\033[0m")
        else:
            client_socket.close()

def main():
    global seed
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 10000))
    server_socket.listen(8)
    print(colors[NUM_COLORS - 1] + "\n\t  ====== Welcome to the chat-room ======   " + "\033[0m")
    while True:
        client_socket, client_address = server_socket.accept()
        seed += 1
        threading.Thread(target=handle_client, args=(client_socket, client_address, seed), daemon=True).start()

if __name__ == "__main__":
    print("Hi")
    main()
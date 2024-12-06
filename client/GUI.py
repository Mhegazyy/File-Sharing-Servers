import socket
import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import tkinter as tk
from tkinter import Tk, filedialog, simpledialog, messagebox, ttk
from tkinter.filedialog import askopenfilename, asksaveasfilename
import hashlib

# Configure logging to output to console for easier debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

session_token = None  # Global session token variable
current_directory = ""  # Track the current directory for navigation
current_username = None  # Track the logged-in username

# Directory for storing the client keys and server's public key
CLIENT_KEY_DIR = os.path.expanduser("D:/TKH/Practical Cryptography/.client_keys")

# Helper functions for dynamic paths
def get_private_key_path():
    if current_username:
        return os.path.join(CLIENT_KEY_DIR, current_username, "client_private_key.pem")
    raise ValueError("Username is not set. Please log in.")

def get_public_key_path():
    if current_username:
        return os.path.join(CLIENT_KEY_DIR, current_username, "client_public_key.pem")
    raise ValueError("Username is not set. Please log in.")

def get_server_public_key_path():
    return os.path.join(CLIENT_KEY_DIR, "server_public_key.pem")

# Ensure directories exist
os.makedirs(CLIENT_KEY_DIR, exist_ok=True)

def retrieve_server_public_key():
    """Fetch the server's public key and save it locally."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    client_socket.sendall("GET_SERVER_PUBLIC_KEY".encode())
    server_public_key = client_socket.recv(1024)
    with open(get_server_public_key_path(), "wb") as key_file:
        key_file.write(server_public_key)
    logging.info("Server's public key retrieved and saved.")
    client_socket.close()

def load_server_public_key():
    """Load the server's public RSA key from file."""
    with open(get_server_public_key_path(), "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def generate_rsa_keys():
    """Generate RSA key pair, store private key securely, and return public key in PEM format."""
    if not current_username:
        raise ValueError("Username is not set. Please log in.")
    user_key_dir = os.path.join(CLIENT_KEY_DIR, current_username)
    os.makedirs(user_key_dir, exist_ok=True)

    private_key_path = get_private_key_path()
    public_key_path = get_public_key_path()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    logging.info("Generated RSA keys successfully.")

def load_private_key():
    """Load the client's private key from file."""
    with open(get_private_key_path(), "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def compute_hash(filepath):
    """Compute the SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while chunk := file.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_file(filepath, aes_key):
    """Encrypt the file data using AES encryption."""
    with open(filepath, 'rb') as file:
        file_data = file.read()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to encrypted data

def encrypt_aes_key_with_rsa(aes_key, server_public_key):
    """Encrypt AES key using the server's RSA public key."""
    return server_public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_file(encrypted_data, aes_key):
    """Decrypt the file data using AES."""
    iv = encrypted_data[:16]  # Extract the IV
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    return decrypted_data

def send_request(command, extra_data="", username="", password=""):
    """Send request to the server."""
    global session_token, current_username
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    if session_token:
        request_data = f"{command} {session_token} {extra_data}"
    elif command == "REGISTER":
        request_data = f"{command} {username} {password} {extra_data.decode()}"
    else:
        request_data = f"{command} {username} {password}"
    client_socket.send(request_data.encode())
    response = client_socket.recv(1024).decode()
    logging.info(f"Server Response: {response}")
    if command == "LOGIN" and "Session token:" in response:
        session_token = response.split("Session token: ")[1].strip()
        current_username = username  # Update the current username
    client_socket.close()

def list_files():
    global session_token
    if not session_token:
        print("You must be logged in to list files.")
        return ""

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    client_socket.send(f"LIST {session_token}".encode())
    response = client_socket.recv(4096).decode()
    client_socket.close()
    print(response)
    return response

def change_directory():
    global session_token, current_directory
    if not session_token:
        print("You must be logged in to change directories.")
        return

    target_directory = input("Enter directory to change to (.. to go up, or a subdirectory): ")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    client_socket.send(f"CD {session_token} {target_directory}".encode())
    response = client_socket.recv(1024).decode()
    if "Changed directory to:" in response:
        current_directory = response.split("Changed directory to: ")[1].strip()
    print(response)
    client_socket.close()

def upload_file():
    global session_token, current_directory

    if not session_token:
        print("You must be logged in to upload files.")
        return

    # Select file to upload
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    filepath = askopenfilename(title="Select a file to upload")
    root.destroy()

    if not filepath:
        print("No file selected.")
        return

    try:
        # Compute file hash
        file_hash = compute_hash(filepath)
        logging.debug(f"SHA-256 hash of file: {file_hash}")

        # Generate AES key and encrypt file data
        aes_key = os.urandom(32)  # 256-bit AES key
        encrypted_file_data = encrypt_file(filepath, aes_key)  # Encrypt the file
        server_public_key = load_server_public_key()
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, server_public_key)
        filename = os.path.basename(filepath)

        # Log details
        logging.debug(f"Original file size: {os.path.getsize(filepath)} bytes.")
        logging.debug(f"Encrypted file size: {len(encrypted_file_data)} bytes.")
        logging.debug(f"Encrypted AES key size: {len(encrypted_aes_key)} bytes.")

        # Establish connection to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", 5000))

        # Construct upload command
        upload_path = filename  # Only send the file name now
        command = f"UPLOAD {session_token} {upload_path}"
        client_socket.send(command.encode())
        response = client_socket.recv(1024).decode()

        if response != "READY":
            print(f"Server Error: {response}")
            return

        # Send file hash
        client_socket.sendall(file_hash.encode())
        logging.debug("Sent file hash to server.")

        # Send encrypted AES key
        client_socket.sendall(encrypted_aes_key)
        logging.debug("Sent encrypted AES key to server.")

        # Send file size
        file_size = len(encrypted_file_data)
        client_socket.sendall(file_size.to_bytes(8, 'big'))
        logging.debug(f"Sent file size: {file_size} bytes to server.")

        # Send encrypted file data in chunks
        CHUNK_SIZE = 4096
        for i in range(0, file_size, CHUNK_SIZE):
            client_socket.sendall(encrypted_file_data[i:i + CHUNK_SIZE])
            logging.debug(f"Sent chunk: {i} to {i + CHUNK_SIZE}.")

        print(f"File '{filename}' uploaded successfully.")
    except Exception as e:
        logging.error(f"Error during upload: {e}")
    finally:
        client_socket.close()
        logging.debug("Client socket closed.")



def download_file():
    """Download a file from the server."""
    logging.debug("Starting the download process...")

    # Fetch the list of files
    response = list_files()
    logging.debug(f"List files response: {response}")

    if "Invalid session token" in response or "Invalid directory" in response:
        logging.error("Error listing files. Invalid session token or directory.")
        return

    # Parse files (only filenames, as the server will resolve the full paths)
    files = [line.replace("[FILE] ", "").strip() for line in response.splitlines() if line.startswith("[FILE]")]
    if not files:
        print("No files available for download.")
        logging.warning("No files available in the current directory.")
        return

    for idx, file_name in enumerate(files):
        print(f"{idx + 1}: {file_name}")

    # Select file
    choice = input("Enter the number of the file to select (or 'cancel' to exit): ")
    logging.debug(f"User selection input: {choice}")
    if choice.lower() == "cancel":
        logging.info("Download operation canceled by user.")
        return

    try:
        choice_index = int(choice) - 1
        selected_file_name = files[choice_index]
        logging.debug(f"Selected file: {selected_file_name}")
    except (ValueError, IndexError):
        print("Invalid selection.")
        logging.warning("User provided invalid input for file selection.")
        return

    # Select save path
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    save_path = asksaveasfilename(initialfile=selected_file_name)
    root.destroy()
    logging.debug(f"User-selected save path: {save_path}")
    if not save_path:
        logging.info("No save path selected. Download aborted.")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", 5000))
        logging.debug("Connection to server established for DOWNLOAD.")

        # Send only the file name to the server
        command = f"DOWNLOAD {session_token} {selected_file_name}"
        logging.debug(f"Sending DOWNLOAD command: {command}")
        client_socket.send(command.encode())

        # Validate server response for AES key size
        aes_key_size_bytes = client_socket.recv(4)
        if not aes_key_size_bytes:
            raise ValueError("No response from server for AES key size.")
        aes_key_size = int.from_bytes(aes_key_size_bytes, 'big')
        logging.debug(f"Received AES key size: {aes_key_size}")

        if aes_key_size <= 0 or aes_key_size > 4096:  # Validate expected size
            raise ValueError(f"Invalid AES key size received: {aes_key_size}")

        # Receive encrypted AES key
        encrypted_aes_key = client_socket.recv(aes_key_size)
        logging.debug(f"Received encrypted AES key of size: {len(encrypted_aes_key)}")
        private_key = load_private_key()
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug("Decrypted AES key successfully.")

        # Receive file size
        file_size_bytes = client_socket.recv(8)
        if not file_size_bytes:
            raise ValueError("No response from server for file size.")
        file_size = int.from_bytes(file_size_bytes, 'big')
        logging.debug(f"Received file size: {file_size}")

        # Receive encrypted file data
        encrypted_file_data = b""
        total_received = 0
        while total_received < file_size:
            chunk = client_socket.recv(min(4096, file_size - total_received))
            if not chunk:
                logging.error("Incomplete file received from server.")
                raise ConnectionError("Connection interrupted during file transfer.")
            encrypted_file_data += chunk
            total_received += len(chunk)
            logging.debug(f"Received {len(chunk)} bytes, Total received: {total_received}/{file_size}")

        # Decrypt file data
        decrypted_file_data = decrypt_file(encrypted_file_data, aes_key)
        logging.debug(f"Decrypted file data successfully. Writing to: {save_path}")

        with open(save_path, "wb") as file:
            file.write(decrypted_file_data)
        logging.info(f"File downloaded and saved successfully to: {save_path}")
        print(f"File downloaded and saved successfully to: {save_path}")

    except Exception as e:
        logging.error(f"Error during file download: {e}")
    finally:
        client_socket.close()
        logging.debug("Client socket closed.")


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Client")
        self.session_token = None
        self.current_directory = "/"
        self.current_username = None

        # Create GUI Elements
        self.create_widgets()

    def create_widgets(self):
        # Top Frame for Login/Registration
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.pack(pady=10)

        ttk.Label(self.top_frame, text="Username:").grid(row=0, column=0, padx=5)
        self.username_entry = ttk.Entry(self.top_frame)
        self.username_entry.grid(row=0, column=1, padx=5)

        ttk.Label(self.top_frame, text="Password:").grid(row=1, column=0, padx=5)
        self.password_entry = ttk.Entry(self.top_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5)

        self.login_button = ttk.Button(self.top_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, pady=5)

        self.register_button = ttk.Button(self.top_frame, text="Register", command=self.register)
        self.register_button.grid(row=2, column=1, pady=5)

        # Middle Frame for File Operations
        self.middle_frame = ttk.Frame(self.root)
        self.middle_frame.pack(pady=10)

        self.upload_button = ttk.Button(self.middle_frame, text="Upload File", command=self.upload_file, state="disabled")
        self.upload_button.grid(row=0, column=0, padx=5)

        self.download_button = ttk.Button(self.middle_frame, text="Download File", command=self.download_file, state="disabled")
        self.download_button.grid(row=0, column=1, padx=5)

        self.list_button = ttk.Button(self.middle_frame, text="List Files", command=self.list_files, state="disabled")
        self.list_button.grid(row=0, column=2, padx=5)

        self.cd_button = ttk.Button(self.middle_frame, text="Change Directory", command=self.change_directory, state="disabled")
        self.cd_button.grid(row=0, column=3, padx=5)

        # Bottom Frame for Logs
        self.log_frame = ttk.Frame(self.root)
        self.log_frame.pack(pady=10)

        self.log_text = tk.Text(self.log_frame, height=10, state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)

    def enable_buttons(self):
        self.upload_button.config(state="normal")
        self.download_button.config(state="normal")
        self.list_button.config(state="normal")
        self.cd_button.config(state="normal")

    def disable_buttons(self):
        self.upload_button.config(state="disabled")
        self.download_button.config(state="disabled")
        self.list_button.config(state="disabled")
        self.cd_button.config(state="disabled")

    def update_log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see("end")

    # Command Functions
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and Password are required!")
            return
        # Implement login logic
        send_request("LOGIN", username=username, password=password)
        if session_token:
            self.session_token = session_token
            self.current_username = username
            self.enable_buttons()
            self.update_log(f"Logged in as: {username}")
        else:
            messagebox.showerror("Error", "Invalid credentials.")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and Password are required!")
            return
        # Implement registration logic
        generate_rsa_keys()
        with open(get_public_key_path(), "rb") as pub_key_file:
            public_key_pem = pub_key_file.read()
        send_request("REGISTER", username=username, password=password, extra_data=public_key_pem)
        self.update_log(f"Registration attempted for {username}.")

    def upload_file(self):
        if not self.session_token:
            messagebox.showerror("Error", "You must log in to upload files!")
            return
        filepath = filedialog.askopenfilename(title="Select a file to upload")
        if not filepath:
            return
        upload_file(filepath)  # Call existing upload logic
        self.update_log(f"File uploaded: {filepath}")

    def download_file(self):
        if not self.session_token:
            messagebox.showerror("Error", "You must log in to download files!")
            return

        # Fetch the list of files
        response = list_files()
        files = [line.replace("[FILE] ", "").strip() for line in response.splitlines() if line.startswith("[FILE]")]
        if not files:
            self.update_log("No files available for download.")
            return

        # Display the files with indexing
        file_list_with_index = "\n".join(f"{idx + 1}: {file}" for idx, file in enumerate(files))
        selected_index = simpledialog.askinteger(
            "Download File", f"Available files:\n{file_list_with_index}\nEnter file index to download:"
        )

        if not selected_index or selected_index < 1 or selected_index > len(files):
            self.update_log("Invalid file index selected.")
            return

        # Map the selected index to a file name
        selected_file = files[selected_index - 1]

        # Ask the user for a save path
        save_path = filedialog.asksaveasfilename(initialfile=selected_file)
        if not save_path:
            self.update_log("Download canceled.")
            return

        # Request file download from the server
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("localhost", 5000))
            command = f"DOWNLOAD {self.session_token} {selected_file}"
            client_socket.send(command.encode())

            # Handle server response
            aes_key_size_bytes = client_socket.recv(4)
            if not aes_key_size_bytes:
                raise ValueError("No response from server for AES key size.")
            aes_key_size = int.from_bytes(aes_key_size_bytes, 'big')

            encrypted_aes_key = client_socket.recv(aes_key_size)
            private_key = load_private_key()
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            file_size_bytes = client_socket.recv(8)
            file_size = int.from_bytes(file_size_bytes, 'big')

            encrypted_file_data = b""
            total_received = 0
            while total_received < file_size:
                chunk = client_socket.recv(min(4096, file_size - total_received))
                if not chunk:
                    raise ConnectionError("Connection interrupted during file transfer.")
                encrypted_file_data += chunk
                total_received += len(chunk)

            # Decrypt the file
            decrypted_file_data = decrypt_file(encrypted_file_data, aes_key)

            # Save the file locally
            with open(save_path, "wb") as file:
                file.write(decrypted_file_data)

            self.update_log(f"File '{selected_file}' downloaded and saved to: {save_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            client_socket.close()

    def list_files(self):
        if not self.session_token:
            messagebox.showerror("Error", "You must log in to list files!")
            return
        response = list_files()
        self.update_log(f"Files:\n{response}")

    def change_directory(self):
        if not self.session_token:
            messagebox.showerror("Error", "You must log in to change directories!")
            return
        target_dir = simpledialog.askstring("Change Directory", "Enter target directory:")
        if target_dir:
            change_directory(target_dir)
            self.update_log(f"Changed directory to: {target_dir}")

# Main Program
if __name__ == "__main__":
    root = Tk()
    app = ClientGUI(root)
    root.mainloop()
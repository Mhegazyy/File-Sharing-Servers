import hashlib
import socket
import os
import uuid
import threading
import logging
from register_user import register_user
from login_user import login_user
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.backends import default_backend

# Configure logging to output to console for easier debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Directory for storing user data and keys
BASE_USER_DIR = "user_data"
active_sessions = {}  # Store active sessions with privilege levels
os.makedirs(BASE_USER_DIR, exist_ok=True)

# Server keys
private_key_path = os.path.join(os.getcwd(), "server_keys", "server_private_key.pem")
public_key_path = os.path.join(os.getcwd(), "server_keys", "server_public_key.pem")

# Load server's private key
with open(private_key_path, "rb") as key_file:
    server_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Load server's public key
with open(public_key_path, "rb") as key_file:
    server_public_key_pem = key_file.read()

# Global variable to control server shutdown
shutdown_server = threading.Event()
lock = threading.Lock()  # For thread safety

def decrypt_file_data(ciphertext, aes_key, iv):
    """Decrypt file data using the provided AES key and IV."""
    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = aes_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise


def list_directory(base_dir, relative_path=""):
    """List the contents of a directory."""
    abs_path = os.path.join(base_dir, relative_path)
    logging.debug(f"Listing directory. Base: {base_dir}, Relative Path: {relative_path}, Absolute Path: {abs_path}")
    if not os.path.exists(abs_path) or not os.path.isdir(abs_path):
        logging.warning(f"Invalid directory access attempt. Path: {abs_path}")
        return "Invalid directory."

    contents = os.listdir(abs_path)
    directory_mapping = {}  # Dictionary to store mappings of filenames to paths
    response = f"Contents of '{relative_path or '/'}':\n"
    for item in contents:
        item_path = os.path.join(relative_path, item)
        abs_item_path = os.path.join(base_dir, item_path)
        directory_mapping[item] = abs_item_path
        if os.path.isdir(abs_item_path):
            response += f"[DIR] {item}\n"
        else:
            response += f"[FILE] {item}\n"
    logging.debug(f"Directory contents: {response}")
    return response, directory_mapping

def handle_download(client_socket, base_dir, session_token, requested_file):
    """Handle the DOWNLOAD command."""
    try:
        logging.debug(f"Handling DOWNLOAD with session_token: {session_token}, requested_file: {requested_file}")

        # Validate session token
        if session_token not in active_sessions:
            logging.warning(f"Invalid session token: {session_token}")
            logging.debug(f"Active sessions: {active_sessions}")
            client_socket.send("Invalid session token.".encode())
            return

        # Retrieve session details
        session_data = active_sessions[session_token]
        username = session_data["username"]
        user_root_directory = session_data["directory"]
        current_directory = session_data["current_directory"].lstrip("/")
        logging.debug(f"Session data for token {session_token}: {session_data}")

        # Resolve the absolute file path
        if requested_file.startswith("/"):
            # Remove leading "/" and resolve relative to the user's directory
            abs_file_path = os.path.abspath(os.path.join(user_root_directory, requested_file.lstrip("/")))
        else:
            # Resolve relative to the current directory
            abs_file_path = os.path.abspath(os.path.join(user_root_directory, current_directory, requested_file))
        logging.debug(f"Resolved absolute file path: {abs_file_path}")

        if not os.path.exists(abs_file_path):
            logging.warning(f"File not found: {abs_file_path}")
            client_socket.send("File not found.".encode())
            return
        if not os.path.isfile(abs_file_path):
            logging.warning(f"Path is not a file: {abs_file_path}")
            client_socket.send("Requested path is not a file.".encode())
            return

        # Read the file
        with open(abs_file_path, "rb") as file:
            file_data = file.read()
        logging.debug(f"Read file of size: {len(file_data)} bytes")

        # Encrypt the file with AES
        aes_key = os.urandom(32)  # 256-bit AES key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
        logging.debug(f"Encrypted file data size: {len(encrypted_data)} bytes")

        # Encrypt the AES key with the client's public RSA key
        client_public_key_path = os.path.join(user_root_directory, f"{username}_public_key.pem")
        logging.debug(f"Looking for client public key at: {client_public_key_path}")

        if not os.path.exists(client_public_key_path):
            logging.warning(f"Client public key not found: {client_public_key_path}")
            client_socket.send("Client public key not found.".encode())
            return

        with open(client_public_key_path, "rb") as key_file:
            client_public_key = serialization.load_pem_public_key(key_file.read())

        encrypted_aes_key = client_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug(f"Encrypted AES key size: {len(encrypted_aes_key)} bytes")

        # Send AES key size and encrypted AES key
        client_socket.sendall(len(encrypted_aes_key).to_bytes(4, 'big'))
        logging.debug("Sent AES key size to client.")
        client_socket.sendall(encrypted_aes_key)
        logging.debug("Sent encrypted AES key to client.")

        # Send file size
        client_socket.sendall(len(encrypted_data).to_bytes(8, 'big'))
        logging.debug(f"Sent file size: {len(encrypted_data)} bytes")

        # Send the encrypted file data
        CHUNK_SIZE = 4096
        total_sent = 0
        for i in range(0, len(encrypted_data), CHUNK_SIZE):
            chunk = encrypted_data[i:i + CHUNK_SIZE]
            client_socket.sendall(chunk)
            total_sent += len(chunk)
            logging.debug(f"Sent chunk of size {len(chunk)}. Total sent: {total_sent}/{len(encrypted_data)}")
        logging.info(f"File transfer complete. Total sent: {total_sent} bytes")

    except Exception as e:
        logging.error(f"Error during DOWNLOAD handling: {e}")
        try:
            client_socket.send(f"Error: {e}".encode())
        except Exception as send_error:
            logging.error(f"Failed to send error message to client: {send_error}")


def handle_client_request(client_socket):
    """Handles requests from clients."""
    client_socket.settimeout(30)  # Timeout to prevent indefinite blocking
    try:
        session_active = True  # Maintain session until client logs out or disconnects
        current_directory = ""  # Track the current directory for traversal
        logging.debug("Client session started. Awaiting requests...")

        while session_active:
            try:
                logging.debug("Waiting to receive data from client...")
                request_data = client_socket.recv(1024).decode()
                if not request_data:  # If no data is received, close the connection
                    logging.info("No data received. Closing connection.")
                    break

                logging.debug(f"Received command data: {request_data}")
                
                # Split the request data into parts
                parts = request_data.split(maxsplit=1)
                logging.debug(f"Split command data into parts (length {len(parts)}): {parts}")
                if len(parts) < 1:  # Validate that at least one part is present
                    logging.warning(f"Malformed request data received: {request_data}")
                    client_socket.send("Invalid command format.".encode())
                    continue

                # Extract the command safely
                command = parts[0]
                logging.debug(f"Extracted command: {command}")

                if command == "REGISTER":
                    try:
                        # Extract username and password
                        parts = request_data.split(maxsplit=3)  # Limit to 3 parts to handle multi-line public keys
                        if len(parts) < 4:
                            raise ValueError("Malformed REGISTER command. Expected: REGISTER <username> <password> <public_key>")

                        username, password, public_key = parts[1], parts[2], parts[3]
                        public_key = " ".join(request_data.split(maxsplit=3)[3:])  # Handle multi-line public key

                        # Register the user
                        register_user(username, password)

                        # Store the public key
                        user_dir = os.path.join(BASE_USER_DIR, username)
                        os.makedirs(user_dir, exist_ok=True)
                        public_key_path = os.path.join(user_dir, f"{username}_public_key.pem")
                        with open(public_key_path, "wb") as key_file:
                            key_file.write(public_key.encode())

                        response = f"Registration successful for {username}."
                        logging.info(response)
                        client_socket.send(response.encode())
                    except Exception as e:
                        logging.error(f"Error in REGISTER command: {e}")
                        client_socket.send(f"Error: {e}".encode())

                elif command == "GET_SERVER_PUBLIC_KEY":
                    try:
                        logging.debug("Sending server public key to client.")
                        client_socket.sendall(server_public_key_pem)
                    except Exception as e:
                        logging.error(f"Error in GET_SERVER_PUBLIC_KEY: {e}")
                        client_socket.send(f"Error: {e}".encode())

                elif command == "LOGIN":
                    try:
                        username, password = parts[1].split()
                        login_success, privilege = login_user(username, password)
                        if login_success:
                            session_token = str(uuid.uuid4())
                            user_dir = os.path.abspath(os.path.join(BASE_USER_DIR, username))  # User's root directory
                            active_sessions[session_token] = {
                                "username": username,
                                "privilege": privilege,
                                "directory": user_dir,  # User's root directory
                                "current_directory": f"/{username}"  # User's directory as the root
                            }
                            logging.debug(f"Session added to active_sessions: {session_token} -> {active_sessions[session_token]}")
                            response = f"Login successful. Session token: {session_token}"
                            logging.info(f"User '{username}' logged in successfully. Session token: {session_token}, Root directory: {user_dir}")
                        else:
                            response = "Login failed."
                            logging.warning(f"Login failed for user: {username}")
                        client_socket.send(response.encode())
                    except Exception as e:
                        logging.error(f"Error in LOGIN command: {e}")
                        client_socket.send(f"Error: {e}".encode())

                elif command == "LOGOUT":
                    try:
                        session_token = parts[1]
                        if session_token in active_sessions:
                            del active_sessions[session_token]
                            response = "Logout successful."
                            session_active = False  # End the session loop on logout
                            logging.info(f"User logged out successfully. Session token: {session_token}")
                        else:
                            response = "Invalid session token. Please log in."
                            logging.warning(f"Invalid session token for logout: {session_token}")
                        client_socket.send(response.encode())
                    except Exception as e:
                        logging.error(f"Error in LOGOUT command: {e}")
                        client_socket.send(f"Error: {e}".encode())

                elif command == "LIST":
                    try:
                        session_token = parts[1].strip()  # Ensure no leading/trailing spaces
                        logging.debug(f"Validating session token for LIST: {session_token}")
                        logging.debug(f"Current active_sessions: {active_sessions}")
                        
                        if session_token in active_sessions:
                            session_data = active_sessions[session_token]
                            username = session_data["username"]
                            current_directory = session_data["current_directory"]

                            base_data_dir = os.path.abspath(BASE_USER_DIR)
                            relative_path = current_directory.lstrip("/")
                            abs_path = os.path.abspath(os.path.join(base_data_dir, relative_path))

                            if abs_path.startswith(base_data_dir) and os.path.exists(abs_path) and os.path.isdir(abs_path):
                                response, directory_mapping = list_directory(base_data_dir, relative_path)
                                # Store the mapping in the session
                                active_sessions[session_token]["directory_mapping"] = directory_mapping
                                logging.debug(f"Directory mapping stored for session: {directory_mapping}")
                            else:
                                response = "Invalid directory or access denied."
                                logging.warning(f"Invalid directory listing attempt at: {abs_path}")
                        else:
                            response = "Invalid session token. Please log in."
                            logging.warning(f"Invalid session token for LIST command: {session_token}")

                        client_socket.send(response.encode())
                    except Exception as e:
                        logging.error(f"Error in LIST command: {e}")
                        client_socket.send(f"Error: {e}".encode())


                elif command == "CD":
                    if len(parts) > 1:  # Ensure the command has at least two parts
                        cd_parts = parts[1].split(maxsplit=1)  # Split to extract session token and target directory
                        logging.debug(f"Split CD data into parts (length {len(cd_parts)}): {cd_parts}")

                        if len(cd_parts) == 2:  # Ensure we have both session token and target directory
                            session_token, target_directory = cd_parts
                        else:  # If no target directory is provided, set it to an empty string
                            session_token = cd_parts[0]
                            target_directory = ""

                        if session_token in active_sessions:
                            # Retrieve session details
                            username = active_sessions[session_token]["username"]
                            user_root_directory = active_sessions[session_token]["directory"]
                            current_directory = active_sessions[session_token]["current_directory"]

                            logging.debug(f"Session token: {session_token}, User root: {user_root_directory}, Current directory: {current_directory}")

                            # Resolve paths relative to the current directory
                            base_data_dir = os.path.abspath(BASE_USER_DIR)
                            target_path = os.path.normpath(os.path.join(current_directory.lstrip("/"), target_directory))
                            abs_path = os.path.abspath(os.path.join(base_data_dir, target_path))

                            logging.debug(f"Resolved target: {target_directory}, Absolute path: {abs_path}")

                            # Validate the absolute path
                            if abs_path.startswith(base_data_dir) and os.path.exists(abs_path) and os.path.isdir(abs_path):
                                # Update current_directory relative to "user_data"
                                current_directory = f"/{os.path.relpath(abs_path, base_data_dir).replace(os.sep, '/')}".rstrip("/")
                                response = f"Changed directory to: {current_directory}"
                                logging.info(f"Directory changed successfully to: {current_directory}")
                            else:
                                response = "Invalid directory or access denied."
                                logging.warning(f"Invalid directory change attempt to {abs_path}")

                            # Save the updated current directory
                            active_sessions[session_token]["current_directory"] = current_directory
                            client_socket.send(response.encode())
                        else:
                            response = "Invalid session token. Please log in."
                            logging.warning(f"Invalid session token for CD command: {session_token}")
                            client_socket.send(response.encode())
                    else:
                        response = "Invalid CD command format."
                        logging.warning(f"Malformed CD command received: {parts}")
                        client_socket.send(response.encode())



                elif command == "DOWNLOAD":
                    if len(parts) > 1:  # Validate that a second part exists for DOWNLOAD
                        raw_download_data = parts[1]
                        download_parts = raw_download_data.split(maxsplit=1)

                        if len(download_parts) == 2:  # Ensure session token and file path exist
                            session_token, requested_file = download_parts
                            if session_token in active_sessions:
                                # Fetch the directory mapping
                                directory_mapping = active_sessions[session_token].get("directory_mapping", {})
                                if requested_file in directory_mapping:
                                    requested_path = directory_mapping[requested_file]
                                    handle_download(client_socket, BASE_USER_DIR, session_token, requested_path)
                                else:
                                    logging.warning(f"Requested file not found in directory mapping: {requested_file}")
                                    client_socket.send("File not found.".encode())
                            else:
                                logging.warning(f"Invalid session token for DOWNLOAD command: {session_token}")
                                client_socket.send("Invalid session token. Please log in.".encode())
                        else:
                            logging.warning(f"DOWNLOAD command received with insufficient arguments: {raw_download_data}")
                            client_socket.send("Invalid DOWNLOAD command format.".encode())
                    else:
                        logging.warning(f"DOWNLOAD command received with insufficient arguments: {request_data}")
                        client_socket.send("Invalid DOWNLOAD command format.".encode())


                elif command == "UPLOAD":
                    if len(parts) > 1:
                        # Split the second part into session token and target file name
                        upload_parts = parts[1].split(maxsplit=1)
                        logging.debug(f"Split UPLOAD data into parts (length {len(upload_parts)}): {upload_parts}")

                        if len(upload_parts) == 2:
                            session_token, target_file_name = upload_parts  # Correctly unpack the split parts
                            if session_token in active_sessions:
                                username = active_sessions[session_token]["username"]
                                user_root_directory = active_sessions[session_token]["directory"]
                                current_directory = active_sessions[session_token]["current_directory"]

                                logging.debug(f"Session token: {session_token}, User root: {user_root_directory}, Current directory: {current_directory}")
                                logging.debug(f"Target file name: {target_file_name}")

                                # Resolve directory
                                if current_directory == f"/{username}" or current_directory == "":
                                    resolved_directory = user_root_directory
                                else:
                                    resolved_directory = os.path.join(user_root_directory, current_directory.lstrip("/"))

                                abs_upload_path = os.path.abspath(os.path.join(resolved_directory, target_file_name))
                                logging.debug(f"Resolved absolute upload path: {abs_upload_path}")

                                # Validate path
                                if abs_upload_path.startswith(user_root_directory) and target_file_name and os.path.exists(os.path.dirname(abs_upload_path)):
                                    try:
                                        # Send "READY" to the client
                                        client_socket.send("READY".encode())
                                        logging.debug("Sent READY to client. Awaiting file hash, AES key, and file data.")

                                        # Receive file hash
                                        file_hash = client_socket.recv(64).decode()
                                        logging.debug(f"Received file hash: {file_hash}")

                                        # Receive encrypted AES key
                                        encrypted_aes_key = client_socket.recv(256)
                                        if not encrypted_aes_key:
                                            raise ValueError("Encrypted AES key not received.")
                                        logging.debug(f"Received encrypted AES key of size: {len(encrypted_aes_key)}")

                                        # Decrypt the AES key
                                        aes_key = server_private_key.decrypt(
                                            encrypted_aes_key,
                                            padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label=None
                                            )
                                        )
                                        logging.debug("Decrypted AES key successfully.")

                                        # Receive file size
                                        file_size_bytes = client_socket.recv(8)
                                        if not file_size_bytes:
                                            raise ValueError("File size not received.")
                                        file_size = int.from_bytes(file_size_bytes, 'big')
                                        logging.debug(f"Expecting file size: {file_size} bytes.")

                                        # Receive encrypted file data
                                        received_data = b""
                                        total_received = 0
                                        while total_received < file_size:
                                            chunk = client_socket.recv(min(4096, file_size - total_received))
                                            if not chunk:
                                                logging.error("Incomplete file data received.")
                                                raise ConnectionError("File transfer interrupted.")
                                            received_data += chunk
                                            total_received += len(chunk)
                                            logging.debug(f"Received {len(chunk)} bytes, Total received: {total_received}/{file_size}")

                                        # Decrypt file data
                                        iv = received_data[:16]
                                        ciphertext = received_data[16:]
                                        decrypted_data = decrypt_file_data(ciphertext, aes_key, iv)

                                        # Verify file integrity
                                        computed_hash = hashlib.sha256(decrypted_data).hexdigest()
                                        logging.debug(f"Computed file hash: {computed_hash}")

                                        if computed_hash != file_hash:
                                            logging.error("File hash mismatch. Upload rejected.")
                                            client_socket.send("Error: File hash mismatch.".encode())
                                            return

                                        # Save the file
                                        with open(abs_upload_path, "wb") as file:
                                            file.write(decrypted_data)
                                        logging.info(f"File uploaded successfully to: {abs_upload_path}")
                                        client_socket.send("Upload successful.".encode())

                                    except Exception as e:
                                        logging.error(f"Error during file upload: {e}")
                                        client_socket.send(f"Error: {e}".encode())
                                else:
                                    logging.warning(f"Invalid or unauthorized upload path: {abs_upload_path}")
                                    client_socket.send("Invalid upload path.".encode())
                            else:
                                logging.warning(f"Invalid session token for UPLOAD command: {session_token}")
                                client_socket.send("Invalid session token. Please log in.".encode())
                        else:
                            logging.warning(f"UPLOAD command received with insufficient arguments: {parts[1]}")
                            client_socket.send("Invalid UPLOAD command format.".encode())
                    else:
                        logging.warning(f"UPLOAD command received with insufficient arguments: {request_data}")
                        client_socket.send("Invalid UPLOAD command format.".encode())




                    

                else:
                    logging.warning(f"Unhandled command: {command}")
                    client_socket.send(f"Command '{command}' not recognized.".encode())
            except ConnectionResetError:
                logging.warning("Client forcibly closed the connection.")
                break

    except socket.timeout:
        logging.warning("Client request timed out.")
        client_socket.send("Request timed out.".encode())
    except Exception as e:
        logging.error(f"Error encountered: {e}")
        client_socket.send(f"Error: {e}".encode())
    finally:
        logging.info("Closing client socket after session ends.")
        client_socket.close()

def start_server_socket():
    """Starts the server socket to listen for client requests."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5000))
    server_socket.listen(5)
    logging.info("Server is listening on port 5000...")

    while not shutdown_server.is_set():
        try:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client_request, args=(client_socket,))
            client_thread.start()
        except OSError:
            break

    logging.info("Server socket has been shut down.")
    server_socket.close()

def main():
    server_thread = threading.Thread(target=start_server_socket)
    server_thread.start()
    server_thread.join()
    logging.info("Server has been shut down.")

if __name__ == "__main__":
    main()

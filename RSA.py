from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_keys(client_name, passphrase=None):
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define the directory for storing keys
    client_keys_dir = f"{client_name}_keys"
    os.makedirs(client_keys_dir, exist_ok=True)

    # Save the private key with optional encryption
    private_key_path = os.path.join(client_keys_dir, f"{client_name}_private_key.pem")
    encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()

    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        )

    # Save the public key
    public_key = private_key.public_key()
    public_key_path = os.path.join(client_keys_dir, f"{client_name}_public_key.pem")

    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Keys generated for {client_name}:")
    print(f"  Private key saved at {private_key_path}")
    print(f"  Public key saved at {public_key_path}")

# Generate keys for clients with optional passphrases
generate_rsa_keys("server")


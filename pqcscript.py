import numpy as np
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Function to generate keys (private and public vectors)
def generate_keys():
    private_key = np.random.randint(1, 10, size=(2,))  # Simple private key vector
    basis_vector = np.array([3, 4])  # Fixed basis vector for simplicity
    public_key = basis_vector * private_key  # Public key derived from basis vector
    return private_key, public_key

# Function to compute the shared secret
def generate_shared_secret(public_key, private_key):
    shared_secret = np.dot(public_key, private_key)  # Dot product for shared secret
    return shared_secret

# Derive a symmetric key from the shared secret
def derive_key(shared_secret):
    # Use KDF to create a symmetric key from the shared secret
    salt = b"pq_salt"  # Fixed salt for simplicity
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(shared_secret.tobytes()))
    return key

# Function to encrypt a message using the derived key
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Function to decrypt a message using the derived key
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Main function for secure messaging simulation
def main():
    # Step 1: Generate key pairs for Alice and Bob
    alice_private, alice_public = generate_keys()
    bob_private, bob_public = generate_keys()

    # Step 2: Generate shared secret from each perspective
    alice_shared_secret = generate_shared_secret(bob_public, alice_private)
    bob_shared_secret = generate_shared_secret(alice_public, bob_private)

    # Step 3: Derive a symmetric key for encryption
    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"
    symmetric_key = derive_key(alice_shared_secret)

    # Step 4: Alice sends an encrypted message to Bob
    message = "Hello, Bob! This is a secure message."
    encrypted_message = encrypt_message(message, symmetric_key)
    print(f"Encrypted Message: {encrypted_message}")

    # Step 5: Bob decrypts the message
    decrypted_message = decrypt_message(encrypted_message, symmetric_key)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()

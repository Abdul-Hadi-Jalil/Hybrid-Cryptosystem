import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
import os
import struct  # For sending data lengths
import chaotic


def generate_rsa_keys():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def serialize_rsa_keys(public_key, private_key):
    """Serialize RSA public and private keys to PEM format."""
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_public_key, pem_private_key

def encrypt_message_with_aes(key, iv, plain_text):
    """Encrypt a message using AES with CBC mode."""
    cipher = Cipher(algorithms.AES(key=key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to ensure block size alignment
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(plain_text) + padder.finalize()

    # Encrypt the padded message
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    return cipher_text

def sign_message(private_key, message):
    """Sign a message using the RSA private key."""
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def sender():
    """Sender function that securely transmits encrypted data and a signature."""
    print("==== Sender Program ====")

    # Generate RSA key pair for the sender
    sender_public_key, sender_private_key = generate_rsa_keys()
    print("\nSender's RSA keys generated successfully.")

    # Serialize RSA keys for transmission
    sender_public_key_pem, sender_private_key_pem = serialize_rsa_keys(sender_public_key, sender_private_key)

    # Create a socket and connect to the receiver
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 65432))
    print("\nConnected to the receiver.")

    try:
        # Receive the receiver's public key
        receiver_public_key_pem = client_socket.recv(1024)
        receiver_public_key = serialization.load_pem_public_key(receiver_public_key_pem)

        # Send the sender's public key to the receiver
        client_socket.sendall(sender_public_key_pem)
        print("Sender's public key sent to the receiver.")

        # Generate an AES key and initialization vector (IV) using chaotic key generation
        aes_key_binary = chaotic.key_generation()
        aes_key = bytes(int(aes_key_binary[i:i+8], 2) for i in range(0, len(aes_key_binary), 8))
        iv = os.urandom(16)  # 16 bytes for AES

        # Encrypt the AES key with the receiver's public RSA key
        encrypted_aes_key = receiver_public_key.encrypt(
            aes_key,
            padd.OAEP(
                mgf=padd.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("AES key encrypted successfully.")

        # Path of dataset
        dataset_path = r"glass.csv"

        # Load the dataset and save its size
        with open(dataset_path, 'r') as f:
            content = f.read()
        
        # Convert dataset to bytes
        content_bytes = content.encode('utf-8')

        # Encrypt the dataset using AES
        encrypted_message = encrypt_message_with_aes(aes_key, iv, content_bytes)
        print(f"Encrypted message: {encrypted_message.hex()}")

        # Sign the encrypted message
        signature = sign_message(sender_private_key, encrypted_message)
        print(f"\nGenerated signature: {signature.hex()}")

        # Send AES key and IV
        client_socket.sendall(encrypted_aes_key)
        client_socket.sendall(iv)

        # Send lengths first (each length is a 4-byte integer)
        client_socket.sendall(struct.pack("!I", len(encrypted_message)))  # Encrypted message length
        client_socket.sendall(struct.pack("!I", len(signature)))  # Signature length

        # Send encrypted message and signature separately
        client_socket.sendall(encrypted_message)
        client_socket.sendall(signature)

        print("\nAll data sent to the receiver.")

    finally:
        client_socket.close()
        print("\nConnection closed.")

if __name__ == "__main__":
    sender()

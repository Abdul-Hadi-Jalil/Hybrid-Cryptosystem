
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
from colorama import Fore, Style, init
import os
import chaotic

# Initialize colorama for terminal colors
init(autoreset=True)

def generate_rsa_keys():
    """
    Generate an RSA key pair.

    Returns:
        tuple: public_key, private_key
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def serialize_rsa_keys(public_key, private_key):
    """
    Serialize RSA public and private keys to PEM format.

    Args:
        public_key: The RSA public key.
        private_key: The RSA private key.

    Returns:
        tuple: PEM-encoded public key and private key.
    """
    # Serialize public key
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serialize private key
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem_public_key, pem_private_key

def encrypt_message_with_aes(key, iv, plain_text):
    """
    Encrypt a message using AES with CBC mode.

    Args:
        key: The AES symmetric key (16 bytes).
        iv: The initialization vector (16 bytes).
        plain_text: The plaintext message to encrypt.

    Returns:
        bytes: The AES-encrypted message.
    """
    cipher = Cipher(algorithms.AES(key=key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to ensure block size alignment
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(plain_text) + padder.finalize()

    # Encrypt the padded message
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    return cipher_text

def sign_message(private_key, message):
    """
    Sign a message using the RSA private key.

    Args:
        private_key: The RSA private key.
        message: The message to sign.

    Returns:
        bytes: The digital signature.
    """
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
    """
    Sender program:
    - Generates RSA keys.
    - Connects to the receiver.
    - Exchanges public keys.
    - Encrypts a message using AES.
    - Signs the message and sends all data to the receiver.
    """
    print(Fore.BLUE + "==== Sender Program ====")

    # Generate RSA key pair for the sender
    sender_public_key, sender_private_key = generate_rsa_keys()
    print(Fore.GREEN + "\nSender's RSA keys generated successfully.")

    # Serialize RSA keys for transmission
    sender_public_key_pem, sender_private_key_pem = serialize_rsa_keys(sender_public_key, sender_private_key)

    # Create a socket and connect to the receiver
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 65432))
    print(Fore.BLUE + "\nConnected to the receiver.")

    try:
        # Receive the receiver's public key
        receiver_public_key_pem = client_socket.recv(1024)
        receiver_public_key = serialization.load_pem_public_key(receiver_public_key_pem)
        print(Fore.YELLOW + f"\nReceived receiver's RSA Public Key:\n{receiver_public_key_pem.decode()}")

        # Send the sender's public key to the receiver
        client_socket.sendall(sender_public_key_pem)
        print(Fore.GREEN + "Sender's public key sent to the receiver.")

        # Generate an AES key and initialization vector (IV) using chaotic key generation
        aes_key_binary = chaotic.key_generation()
        aes_key = bytes(int(aes_key_binary[i:i+8], 2) for i in range(0, len(aes_key_binary), 8))
        iv = os.urandom(16)  # 16 bytes for AES

        print(Fore.GREEN + f"\nGenerated AES Key: {aes_key.hex()}")
        print(Fore.GREEN + f"Generated IV: {iv.hex()}")

        # Encrypt the AES key with the receiver's public RSA key
        encrypted_aes_key = receiver_public_key.encrypt(
            aes_key,
            padd.OAEP(
                mgf=padd.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(Fore.GREEN + "AES key encrypted successfully.")

        # Encrypt a sample message using AES
        message = b"This is a secure message."
        encrypted_message = encrypt_message_with_aes(aes_key, iv, message)
        print(Fore.GREEN + f"Encrypted message: {encrypted_message}")

        # Sign the encrypted message
        signature = sign_message(sender_private_key, encrypted_message)
        print(Fore.GREEN + f"Generated signature: {signature}")

        # Send all data to the receiver
        client_socket.sendall(encrypted_aes_key)
        client_socket.sendall(iv)
        client_socket.sendall(encrypted_message)
        client_socket.sendall(signature)
        print(Fore.BLUE + "\nAll data sent to the receiver.")

    finally:
        client_socket.close()
        print(Fore.BLUE + "\nConnection closed.")

if __name__ == "__main__":
    sender()

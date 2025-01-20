import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
from colorama import Fore, Style, init

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

def decrypt_message_with_aes(key, iv, cipher_text):
    """
    Decrypt an AES-encrypted message using CBC mode.

    Args:
        key: The AES symmetric key (16, 24, or 32 bytes).
        iv: The initialization vector (16 bytes).
        cipher_text: The encrypted message.

    Returns:
        bytes: The decrypted plaintext message.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt and remove padding
    decrypted_padded_text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
    return plain_text

def verify_signature(public_key, message, signature):
    """
    Verify the digital signature of a message.

    Args:
        public_key: The RSA public key used for verification.
        message: The original message that was signed.
        signature: The digital signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(Fore.RED + f"Signature verification failed: {e}")
        return False

def receiver():
    """
    Receiver program:
    - Generates RSA keys.
    - Listens for incoming connections.
    - Exchanges public keys with the sender.
    - Receives encrypted AES key, IV, encrypted message, and signature.
    - Decrypts the AES key and message.
    - Verifies the message signature.
    """
    print(Fore.BLUE + "==== Receiver Program ====")

    # Generate RSA key pair for the receiver
    receiver_public_key, receiver_private_key = generate_rsa_keys()
    print(Fore.GREEN + "\nReceiver's RSA keys generated successfully.")

    # Serialize RSA keys for transmission
    receiver_public_key_pem, receiver_private_key_pem = serialize_rsa_keys(receiver_public_key, receiver_private_key)

    # Create a socket and bind to localhost
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    recv_socket.bind(("localhost", 65432))
    recv_socket.listen(1)
    print(Fore.BLUE + "\nWaiting for a connection...")

    connection, client_address = recv_socket.accept()

    try:
        print(Fore.GREEN + f"\nConnection established with {client_address}.")

        # Send receiver's public key to the sender
        connection.sendall(receiver_public_key_pem)
        print(Fore.GREEN + "Receiver's public key sent to the sender.")

        # Receive sender's public key
        sender_public_key_pem = connection.recv(1024)
        sender_public_key = serialization.load_pem_public_key(sender_public_key_pem)
        print(Fore.YELLOW + f"\nReceived sender's RSA Public Key:\n{sender_public_key_pem.decode()}")

        # Receive encrypted AES key, IV, encrypted message, and signature
        encrypted_aes_key = connection.recv(256)  # Assuming RSA key size is 2048 bits (256 bytes)
        iv = connection.recv(16)  # IV is 16 bytes for AES
        encrypted_message = connection.recv(1024)
        signature = connection.recv(1024)

        # Decrypt the AES key using the receiver's private key
        aes_key = receiver_private_key.decrypt(
            encrypted_aes_key,
            padd.OAEP(
                mgf=padd.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(Fore.GREEN + f"Decrypted AES Key: {aes_key}")

        # Verify the signature of the encrypted message
        if verify_signature(sender_public_key, encrypted_message, signature):
            print(Fore.GREEN + "Signature verification successful.")
        else:
            print(Fore.RED + "Signature verification failed.")

        # Decrypt the message using AES
        decrypted_message = decrypt_message_with_aes(aes_key, iv, encrypted_message)
        print(Fore.GREEN + f"Decrypted message: {decrypted_message.decode()}")

    finally:
        connection.close()
        print(Fore.BLUE + "\nConnection closed.")

if __name__ == "__main__":
    receiver()

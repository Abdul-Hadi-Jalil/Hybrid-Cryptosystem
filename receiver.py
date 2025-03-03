import socket
import struct  # For handling message sizes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding


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

def decrypt_message_with_aes(key, iv, cipher_text):
    """Decrypt an AES-encrypted message using CBC mode."""
    cipher = Cipher(algorithms.AES(key=key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt and remove padding
    decrypted_padded_text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
    return plain_text

def verify_signature(public_key, message, signature):
    """Verify the digital signature of a message."""
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
        print(f"Signature verification failed: {e}")
        return False

def recv_all(sock, length):
    """Helper function to receive a specific amount of bytes."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))  # Ensure we receive exactly `length` bytes
        if not chunk:
            break
        data += chunk
    print(f"Received {len(data)} bytes, expected {length}")  # Debugging info
    return data


def receiver():
    """Receiver function that securely receives and processes encrypted data."""
    print("==== Receiver Program ====")

    # Generate RSA key pair for the receiver
    receiver_public_key, receiver_private_key = generate_rsa_keys()
    print("\nReceiver's RSA keys generated successfully.")

    # Serialize RSA keys for transmission
    receiver_public_key_pem, receiver_private_key_pem = serialize_rsa_keys(receiver_public_key, receiver_private_key)

    # Create a socket and bind to localhost
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    recv_socket.bind(("localhost", 65432))
    recv_socket.listen(1)
    print("\nWaiting for a connection...")

    connection, client_address = recv_socket.accept()

    try:
        print(f"\nConnection established with {client_address}.")

        # Send receiver's public key to the sender
        connection.sendall(receiver_public_key_pem)
        print("Receiver's public key sent to the sender.")

        # Receive sender's public key
        sender_public_key_pem = connection.recv(1024)
        sender_public_key = serialization.load_pem_public_key(sender_public_key_pem)

        # Receive AES key and IV
        encrypted_aes_key = recv_all(connection, 256)  # 2048-bit RSA encryption results in 256 bytes
        iv = recv_all(connection, 16)  # IV is 16 bytes for AES

        # Receive lengths first
        encrypted_msg_length = struct.unpack("!I", recv_all(connection, 4))[0]  # Read 4 bytes for message length
        signature_length = struct.unpack("!I", recv_all(connection, 4))[0]  # Read 4 bytes for signature length

        # Receive encrypted message and signature based on received lengths
        encrypted_message = recv_all(connection, encrypted_msg_length)
        signature = recv_all(connection, signature_length)

        print(f"\nReceived encrypted message {encrypted_message}")
        print(f"\n Received signature {signature}")

        print(f"\nReceived Encrypted Message (Size: {encrypted_msg_length} bytes)")
        print(f"Received Signature (Size: {signature_length} bytes)")

        # Decrypt the AES key using the receiver's private key
        aes_key = receiver_private_key.decrypt(
            encrypted_aes_key,
            padd.OAEP(
                mgf=padd.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted AES Key: {aes_key.hex()}")

        # Verify the signature of the encrypted message
        if verify_signature(sender_public_key, encrypted_message, signature):
            print("Signature verification successful.")
        else:
            print("Signature verification failed.")

        # Decrypt the message using AES
        decrypted_message = decrypt_message_with_aes(aes_key, iv, encrypted_message)

        print(f"\nDecrypted message:\n{decrypted_message.decode('utf-8')[:500]}")  # Print first 500 chars

        # Save the decrypted data to a CSV file
        with open("received_file.csv", "w", encoding="utf-8") as f:
            f.write(decrypted_message.decode("utf-8"))

        print("\nCSV file has been successfully restored as 'received_file.csv'.")
    finally:
        connection.close()
        print("\nConnection closed.")

if __name__ == "__main__":
    receiver()

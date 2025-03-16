import time
import tracemalloc
from sender import generate_rsa_keys, serialize_rsa_keys, encrypt_message_with_aes, sign_message
from receiver import decrypt_message_with_aes, verify_signature, recv_all

def measure_resources(func):
    """Decorator to measure time and memory usage of a function."""
    def wrapper(*args, **kwargs):
        tracemalloc.start()
        start_time = time.time()

        result = func(*args, **kwargs)

        elapsed_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"{func.__name__} - Time: {elapsed_time:.4f}s, Memory: {peak / 1024:.2f}KB")
        return result
    return wrapper

# Test functions one by one
@measure_resources
def test_generate_rsa_keys():
    return generate_rsa_keys()

@measure_resources
def test_serialize_rsa_keys(public_key, private_key):
    return serialize_rsa_keys(public_key, private_key)

@measure_resources
def test_encrypt_message_with_aes(key, iv, plain_text):
    return encrypt_message_with_aes(key, iv, plain_text)

@measure_resources
def test_sign_message(private_key, message):
    return sign_message(private_key, message)

@measure_resources
def test_decrypt_message_with_aes(key, iv, cipher_text):
    return decrypt_message_with_aes(key, iv, cipher_text)

@measure_resources
def test_verify_signature(public_key, message, signature):
    return verify_signature(public_key, message, signature)

@measure_resources
def test_recv_all(sock, length):
    return recv_all(sock, length)

if __name__ == "__main__":
    # Test generate_rsa_keys
    print("Testing generate_rsa_keys...")
    public_key, private_key = test_generate_rsa_keys()

    # Test serialize_rsa_keys
    print("\nTesting serialize_rsa_keys...")
    pem_public_key, pem_private_key = test_serialize_rsa_keys(public_key, private_key)

    # Test encrypt_message_with_aes
    print("\nTesting encrypt_message_with_aes...")
    aes_key = b"1234567890123456"  # Example AES key
    iv = b"1234567890123456"      # Example IV
    plain_text = b"Hello, this is a test message."
    encrypted_message = test_encrypt_message_with_aes(aes_key, iv, plain_text)

    # Test sign_message
    print("\nTesting sign_message...")
    signature = test_sign_message(private_key, encrypted_message)

    # Test decrypt_message_with_aes
    print("\nTesting decrypt_message_with_aes...")
    decrypted_message = test_decrypt_message_with_aes(aes_key, iv, encrypted_message)

    # Test verify_signature
    print("\nTesting verify_signature...")
    is_signature_valid = test_verify_signature(public_key, encrypted_message, signature)
    print(f"Signature valid: {is_signature_valid}")

    # Test recv_all (requires a socket connection, so it's mocked here)
    print("\nTesting recv_all...")
    class MockSocket:
        def recv(self, length):
            return b"mock_data" * length
    mock_sock = MockSocket()
    test_recv_all(mock_sock, 10)
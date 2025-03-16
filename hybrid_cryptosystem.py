import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
from colorama import Fore, Style, init
import os
import chaotic

class HybridCryptosystem:
    def __init__(self):
        pass

    def select_algo(self, algorithm: str):
        self.algo = algorithm


# Hybrid-Cryptosystem

# Secure Dataset Transmission

This project demonstrates secure transmission of datasets using RSA encryption, AES encryption, and digital signatures. It consists of a sender and receiver program, along with a resource testing script.

## Features
- **RSA Key Generation**: Generate RSA public and private keys.
- **AES Encryption**: Encrypt datasets using AES in CBC mode.
- **Digital Signatures**: Sign messages using RSA private keys.
- **Resource Testing**: Measure time and memory usage for each function.

## Requirements
- Python 3.7+
- Required Python packages (see `requirements.txt`).

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
Install dependencies:

bash
Copy
pip install -r requirements.txt
Usage
Run the Sender and Receiver:

Start the receiver first:

bash
Copy
python receiver.py
Then run the sender:

bash
Copy
python sender.py
Test Resource Usage:

Run the testing script:

bash
Copy
python test_resources.py
Files
sender.py: Sender program for encrypting and sending datasets.

receiver.py: Receiver program for decrypting and verifying datasets.

test_resources.py: Script to measure time and memory usage of functions.

requirements.txt: List of required Python packages.
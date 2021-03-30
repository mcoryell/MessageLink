import os
import socket
import sys
import json

from base64 import b64encode
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as p

HOST = '35.185.50.240'  # The server's hostname or IP address
PORT = 30330            # The port used by the server


def create_aes_info():
    aes_info = {
        'key': os.urandom(32),
        'iv': os.urandom(16)
    }

    return aes_info

def encrypt_aes_info(aes_info, server_public_key):
    ciphertext = server_public_key.encrypt(
        aes_info,
        p.OAEP(
            mgf=p.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )

    return ciphertext


def encrypt_message(message, aes_info):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    encryptor = cipher.encryptor()

    # Pad the message to be a multiple of 128 bits for the AES algorithm
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Encrypt the data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text


def decrypt_message(encrypted_server_response, aes_info):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    decrypter = cipher.decryptor()

    # Decrypt the data
    padded_server_response = decrypter.update(encrypted_server_response) + decrypter.finalize()

    # Unpad the server response message
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_server_response = unpadder.update(padded_server_response) + unpadder.finalize()
    return decrypted_server_response


def main():
    # Initialize client program with welcome prompt
    print('Welcome to MessageLink!')
    print('Status: A new MessageLink Client connection is being created.\n')

    # Create the AES key and iv
    aes_info = create_aes_info()
    prepped_aes_info = {
        'key': b64encode(aes_info['key']).decode('utf-8'),
        'iv': b64encode(aes_info['iv']).decode('utf-8')
    }

    print('AES-256 Key (Base64 Encoded):\n', prepped_aes_info['key'], '\n', sep='')
    print('AES-256 Initial Value (Base64 Encoded):\n', prepped_aes_info['iv'], '\n', sep='')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow the client to connect
        s.connect((HOST, PORT))
        print('Status: Connection has been established.\n')

        # Receive server's public key
        server_public_key_bytes = s.recv(1024)
        print('Server Public Key:\n\n', server_public_key_bytes.decode('utf-8'), sep='')

        # The server's public key is in bytes and needed to be converted to an RSA public key object
        server_public_key = load_pem_public_key(server_public_key_bytes)

        # Share AES info with the server
        s.send(encrypt_aes_info(json.dumps(prepped_aes_info).encode('utf-8'), server_public_key))

        while True:
            message = input("Message to Send: ")
            s.send(encrypt_message(message, aes_info))
            encrypted_server_response = s.recv(1024)
            if message == 'MessageLink -terminate':
                break
            decrypted_server_response = decrypt_message(encrypted_server_response, aes_info)
            print('Ciphertext received from server: ', encrypted_server_response, sep='')
            print(decrypted_server_response.decode('utf-8'))

        s.close()


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Additional command line arguments are unnecessary to run this program.')
        exit()

    main()

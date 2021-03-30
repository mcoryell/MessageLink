import socket
import sys
import json
import signal
from _thread import *

from base64 import b64decode
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as p

HOST = '0.0.0.0'  # Listen from any IP
PORT = 30330  # Port to listen on (non-privileged ports are > 1023)
client_list = []  # List to hold all the connections of clients


def create_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    keys = {
        'public_key': public_key,
        'private_key': private_key
    }
    return keys


def decrypt_aes_info(aes_info, server_private_key):
    plaintext = server_private_key.decrypt(
        aes_info,
        p.OAEP(
            mgf=p.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )

    return plaintext


def encrypt_message(server_response, aes_info):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    encryptor = cipher.encryptor()

    # Pad the server response to be a multiple of 128 bits for the AES algorithm
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(server_response.encode()) + padder.finalize()

    # Encrypt the data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text


def decrypt_message(encrypted_message, aes_info):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    decrypter = cipher.decryptor()

    # Decrypt the data
    padded_message = decrypter.update(encrypted_message) + decrypter.finalize()

    # Unpad the server response message
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()
    return decrypted_message


def client_thread(client):
    while True:
        data = client['connection'].recv(1024)
        decrypted_data = decrypt_message(data, client['aes_info'])
        if decrypted_data.decode('utf-8') == 'MessageLink -terminate':
            break
        print('Ciphertext received from ', client['ip_address'], ': ', data, sep='')
        print('Message received from ', client['ip_address'], ': ', decrypted_data.decode('utf-8'), sep='')
        server_response = 'Server Response: Message has been received as \'' + decrypted_data.decode('utf-8') + '\''
        client['connection'].send(encrypt_message(server_response, client['aes_info']))

    print('Status: A MessageLink Client with IP Address, ', client['ip_address'], ', has disconnected.', sep='')
    client['connection'].close()
    client_list.remove(client)


def main():
    # Initialize server program with welcome prompt
    print('Welcome to MessageLink!')
    print('Status: A new MessageLink Server is being created.')

    rsa_keys = create_rsa_keys()

    server_public_key = rsa_keys['public_key'].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('Server Public Key:\n\n', server_public_key.decode('utf-8'), sep='')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
        except OSError:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            print("Unable to bind socket. Please try to run the program again!\n")
            exit()

        print('Status: Currently awaiting a connection.')
        s.listen(100)  # Listens for up to 100 client connections

        try:
            while True:
                # Allow the client to connect
                conn, addr = s.accept()
                print('Status: A new MessageLink Client connection has been established. Client:', addr[0], '\n')

                # Share server public key with client
                conn.send(server_public_key)

                # Retrieve AES key and iv from client
                decrypted_aes_info = decrypt_aes_info(conn.recv(1024), rsa_keys['private_key'])
                prepped_aes_info = json.loads(decrypted_aes_info.decode('utf-8'))
                print('AES-256 Key (Base64 Encoded) used in Connection with ', addr[0], ':\n',
                      prepped_aes_info['key'], '\n', sep='')
                print('AES-256 Initial Value (Base64 Encoded) used in Connection with ', addr[0], ':\n',
                      prepped_aes_info['iv'], '\n', sep='')

                # Add the new client connection to the list.
                # Note: The client's aes info is in base64 encoded strings and needed to be converted to bytes
                aes_info = {
                    'key': b64decode(prepped_aes_info['key']),
                    'iv': b64decode(prepped_aes_info['iv'])
                }

                client = {
                    "connection": conn,
                    "ip_address": addr[0],
                    "aes_info": aes_info,
                }
                client_list.append(client)

                # Start messaging
                start_new_thread(client_thread, (client,))
        except KeyboardInterrupt:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            print("\n\nThank you for running MessageLink Server!\n")


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Additional command line arguments are unnecessary to run this program.')
        exit()

    main()

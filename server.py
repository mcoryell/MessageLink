import socket
import sys
from _thread import *

from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as p

HOST = '0.0.0.0'  # Listen from any IP
PORT = 30330  # Port to listen on (non-privileged ports are > 1023)
client_list = []  # List to hold all the connections of clients


def load_aes_info():
    key_file = open("key.bin", "rb")
    iv_file = open("iv.bin", "rb")
    aes_info = {
        'key': key_file.read(),
        'iv': iv_file.read()
    }
    return aes_info


def create_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    keys = {
        'public_key': public_key,
        'private_key': private_key
    }
    return keys


def encrypt_server_public_key(aes_info, rsa_keys):
    # Create an encryption context
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    encryptor = cipher.encryptor()

    # Get the RSA public key data
    pem = rsa_keys['public_key'].public_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Pad the RSA key to be a multiple of 128 bits for the AES algorithm
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(pem) + padder.finalize()

    # Encrypt the data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text


def decrypt_client_public_key(encrypted_client_public_key, aes_info):
    # Create a decryption context
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    decrypter = cipher.decryptor()

    # Decrypt the data
    padded_client_public_key = decrypter.update(encrypted_client_public_key) + decrypter.finalize()

    # Unpad the RSA key
    unpadder = padding.PKCS7(128).unpadder()
    client_public_key = unpadder.update(padded_client_public_key) + unpadder.finalize()

    return client_public_key


def encrypt_message(message, client_public_key):
    ciphertext = client_public_key.encrypt(
        str.encode(message),
        p.OAEP(
            mgf=p.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )

    return ciphertext


def decrypt_message(message, server_private_key):
    plaintext = server_private_key.decrypt(
        message,
        p.OAEP(
            mgf=p.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )

    return plaintext


def client_thread(client, rsa_keys):
    while True:
        data = client['connection'].recv(1024)
        decrypted_data = decrypt_message(data, rsa_keys['private_key'])
        if decrypted_data.decode('utf-8') == 'MessageLink -terminate':
            break
        print('Ciphertext received from ', client['ip_address'], ': ', data, sep='')
        print('Message received from ', client['ip_address'], ': ', decrypted_data.decode('utf-8'), sep='')
        server_response = 'Server Response: Message has been received as \'' + decrypted_data.decode('utf-8') + '\''
        client['connection'].send(encrypt_message(server_response, client['public_key']))

    print('Status: A MessageLink Client with IP Address, ', client['ip_address'], ', has disconnected.', sep='')
    client['connection'].close()
    client_list.remove(client)


def main():
    # Initialize server program with welcome prompt
    print('Welcome to MessageLink!')
    print('Status: A new MessageLink Server is being created.')

    # Load AES key and iv, create public/private RSA key pair, print the server's public key, and encrypt the
    # server's public key
    aes_info = load_aes_info()
    rsa_keys = create_rsa_keys()
    server_public_key = rsa_keys['public_key'].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('Server Public Key:\n\n', server_public_key.decode('utf-8'), sep='')
    encrypted_server_public_key = encrypt_server_public_key(aes_info, rsa_keys)

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
                print('Status: A new MessageLink Client connection has been established. Client:', addr[0])

                # Swap public keys
                decrypted_client_public_key = decrypt_client_public_key(conn.recv(1024), aes_info)
                print('Public Key from Client (', addr[0], '):\n\n', decrypted_client_public_key.decode('utf-8'), sep='')
                conn.send(encrypted_server_public_key)

                # Add the new client connection to the list.
                # Note: The client's public key is in bytes and needed to be converted to an RSA public key object
                client = {
                    "connection": conn,
                    "ip_address": addr[0],
                    "public_key": load_pem_public_key(decrypted_client_public_key)
                }
                client_list.append(client)

                # Start messaging
                start_new_thread(client_thread, (client, rsa_keys,))

        except KeyboardInterrupt:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            print("\n\nThank you for running MessageLink Server!\n")


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Additional command line arguments are unnecessary to run this program.')
        exit()

    main()

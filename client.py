import socket
import sys

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = '35.185.50.240'  # The server's hostname or IP address
PORT = 30330            # The port used by the server


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


def encrypt_client_public_key(aes_info, rsa_keys):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    encryptor = cipher.encryptor()
    pem = rsa_keys['public_key'].public_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # Pad the RSA key to be a multiple of 128 bits for the AES algorithm
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(pem) + padder.finalize()

    # Encrypt the data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text


def decrypt_server_public_key(encrypted_client_public_key, aes_info):
    cipher = Cipher(algorithms.AES(aes_info['key']), modes.CBC(aes_info['iv']))
    decrypter = cipher.decryptor()

    # Decrypt the data
    padded_server_public_key = decrypter.update(encrypted_client_public_key) + decrypter.finalize()

    # Unpad the RSA key
    unpadder = padding.PKCS7(128).unpadder()
    server_public_key = unpadder.update(padded_server_public_key) + unpadder.finalize()
    return server_public_key


def swap_public_keys(encrypted_client_public_key, s, aes_info):
    s.send(encrypted_client_public_key)
    encrypted_server_public_key = s.recv(1024)
    return decrypt_server_public_key(encrypted_server_public_key, aes_info)


def main():
    # Initialize client program with welcome prompt
    print('Welcome to MessageLink!')
    print('Status: A new MessageLink Client connection is being created.')

    # Load AES key and iv, create public/private RSA key pair, print the client's public key, and encrypt the
    # client's public key
    aes_info = load_aes_info()
    rsa_keys = create_rsa_keys()
    client_public_key = rsa_keys['public_key'].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('Client Public Key:\n\n', client_public_key.decode('utf-8'), sep='')
    encrypted_client_public_key = encrypt_client_public_key(aes_info, rsa_keys)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow the client to connect
        s.connect((HOST, PORT))
        print('Status: Connection has been established.\n')

        # Swap public keys
        decrypted_server_public_key = swap_public_keys(encrypted_client_public_key, s, aes_info)
        print('Server Public Key:\n\n', decrypted_server_public_key.decode('utf-8'), sep='')

        # The server's public key is in bytes and needed to be converted to an RSA public key object
        server_rsa_public_key = load_pem_public_key(decrypted_server_public_key)

        while True:
            # Need to encrypt the message with server's public key (server_rsa_public_key)
            message = input("Message to Send: ")
            s.send(str.encode(message))
            server_response = s.recv(1024)
            if message == 'MessageLink -terminate':
                break
            print(server_response.decode('utf-8'))

        s.close()


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Additional command line arguments are unnecessary to run this program.')
        exit()

    main()

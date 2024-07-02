import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from utils import deserialize_private_key, deserialize_public_key, load_private_key, load_public_key, serialize_public_key

class Client:
    def __init__(self, username, server_host='localhost', server_port=12345):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((server_host, server_port))
        self.private_key, self.public_key = self.load_client_keys()
        self.server_public_key = self.load_server_public_key()
        self.register()

    def load_server_public_key(self):
        # Loading the server's public key
        with open('server_public_key.pem', 'rb') as f:
            server_public_key_pem = f.read()
            print(f"The server's public key has been loaded: {server_public_key_pem.decode('utf-8')}")
            return deserialize_public_key(server_public_key_pem)

    def load_client_keys(self):
        # Load the private and public keys for the client
        private_key = load_private_key('ezgi_private_key.pem')
        public_key = load_public_key('ezgi_public_key.pem')
        return private_key, public_key

    def register(self):
        # Registering the client
        public_key_pem = serialize_public_key(self.public_key).decode('utf-8')
        print(f"Recording with the public key: {public_key_pem}")
        self.client_socket.send(f'REGISTER {self.username} {public_key_pem}'.encode('utf-8'))
        response = self.client_socket.recv(4096).decode('utf-8')
        print(f"Recording response: {response}")

    def post_image(self, image_path):
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        # Creating the AES key and encrypting the image
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_image = self.pad(image_data)
        encrypted_image = encryptor.update(padded_image) + encryptor.finalize()
        
       # Encrypting the AES key with the server's public key
        aes_key_encrypted = self.server_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
       # Signing the image
        signature = self.private_key.sign(
            encrypted_image,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Sending to the server
        self.client_socket.send(f'POST_IMAGE {os.path.basename(image_path)}'.encode('utf-8'))
        ack = self.client_socket.recv(4096).decode('utf-8')
        if ack == 'ACK':
            self.send_data(encrypted_image, "encrypted image")
            self.send_data(signature, "signature")
            self.send_data(aes_key_encrypted, "encrypted AES key")
            self.send_data(iv, "IV")
        
        print("Encrypted image has been sent")
        print("Signature has been sent")
        print("Encrypted AES key has been sent")
        print("IV sent")

    def send_data(self, data, data_type):
        # Sending the data to the server
        data_length = len(data)
        self.client_socket.send(f'{data_type} {data_length}'.encode('utf-8'))
        ack = self.client_socket.recv(4096).decode('utf-8')
        if ack == 'ACK':
            self.client_socket.send(data)
            print(f"{data_type} gönderildi")

    def pad(self, data):
        # PKCS#7 padding
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def download_image(self, image_name):
        # Downloading images
        self.client_socket.send(f'DOWNLOAD {image_name}'.encode('utf-8'))
        response = self.client_socket.recv(4096).decode('utf-8')
        print(f"Sunucu yanıtı: {response}")
        if response.startswith('SENDING_IMAGE'):
            encrypted_image = self.receive_data("encrypted image")
            signature = self.receive_data("signature")
            encrypted_aes_key = self.receive_data("encrypted AES key")
            iv = self.receive_data("IV")

            # Decrypting the AES key
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypting images
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_image = decryptor.update(encrypted_image) + decryptor.finalize()
            decrypted_image = self.unpad(decrypted_image)

            # Storing images
            with open(f'downloaded_{image_name}', 'wb') as f:
                f.write(decrypted_image)
            print(f"The image {image_name} has been downloaded and saved as downloaded_{image_name}")
        else:
            print(f"Image could not be downloaded: {image_name}")

    def receive_data(self, data_type):
        # Getting data from the server
        header = self.client_socket.recv(4096).decode('utf-8')
        if data_type in header:
            self.client_socket.send('ACK'.encode('utf-8'))
            data_length = int(header.split()[-1])
            data = b''
            while len(data) < data_length:
                data += self.client_socket.recv(data_length - len(data))
            print(f"{data_type} received, length: {len(data)}")
            return data

    def unpad(self, data):
        # PKCS#7 unpadding
        pad_len = data[-1]
        return data[:-pad_len]

if __name__ == '__main__':
    username = input("Enter your username: ")
    client = Client(username)
    while True:
        command = input("Enter the command (post / download / exit): ").strip()
        if command == 'post':
            image_path = input("Enter the path of the image you want to send: ")
            client.post_image(image_path)
        elif command == 'download':
            image_name = input("Enter the name of the image you want to download: ")
            client.download_image(image_name)
        elif command == 'exit':
            break
        else:
            print("Invalid command. Please enter 'post', 'download' or 'exit'.")

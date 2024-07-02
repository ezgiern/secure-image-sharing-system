import tkinter as tk
from tkinter import messagebox
import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from utils import deserialize_private_key, deserialize_public_key, load_private_key, load_public_key, serialize_public_key

class Client:
    def __init__(self, server_host='localhost', server_port=12345):
        self.server_host = server_host
        self.server_port = server_port
        # Creating the client socket and connecting to the server
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((server_host, server_port))
        # Loading client keys
        self.private_key, self.public_key = self.load_client_keys()
        # Loading the server public key
        self.server_public_key = self.load_server_public_key()

    def load_server_public_key(self):
      # Loading the server public key
        with open('server_public_key.pem', 'rb') as f:
            server_public_key_pem = f.read()
            return deserialize_public_key(server_public_key_pem)

    def load_client_keys(self):
        # Loading the client private and public keys
        private_key = load_private_key('ezgi_private_key.pem')
        public_key = load_public_key('ezgi_public_key.pem')
        return private_key, public_key

    def register(self, username):
        # Saving the client to the server
        public_key_pem = serialize_public_key(self.public_key).decode('utf-8')
        self.client_socket.send(f'REGISTER {username} {public_key_pem}'.encode('utf-8'))
        response = self.client_socket.recv(4096).decode('utf-8')
        print(f"Recording response: {response}")
        return response.startswith("REGISTERED")

    def post_image(self, image_path):
        # Reading image from the file
        with open(image_path, 'rb') as f:
            image_data = f.read()

     # Creating the AES key and official encryption
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_image = self.pad(image_data)
        encrypted_image = encryptor.update(padded_image) + encryptor.finalize()

       # Encrypting the AES key with the server public key
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

        # Sending images to the server
        self.client_socket.send(f'POST_IMAGE {os.path.basename(image_path)}'.encode('utf-8'))
        ack = self.client_socket.recv(4096).decode('utf-8')
        if ack == 'ACK':
            self.send_data(encrypted_image, "encrypted image")
            self.send_data(signature, "signature")
            self.send_data(aes_key_encrypted, "encrypted AES key")
            self.send_data(iv, "IV")
        print("Encrypted image has been sent")

    def send_data(self, data, data_type):
        # Sending the data to the server
        data_length = len(data)
        self.client_socket.send(f'{data_type} {data_length}'.encode('utf-8'))
        ack = self.client_socket.recv(4096).decode('utf-8')
        if ack == 'ACK':
            self.client_socket.send(data)
            print(f"{data_type} sent")

    def pad(self, data):
        # PKCS#7 padding
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def download_image(self, image_name):
        # Downloading images
        self.client_socket.send(f'DOWNLOAD {image_name}'.encode('utf-8'))
        response = self.client_socket.recv(4096).decode('utf-8')
        print(f"Server response: {response}")
        if response.startswith('SENDING_IMAGE'):
            encrypted_image = self.receive_data("encrypted image")
            signature = self.receive_data("signature")
            encrypted_aes_key = self.receive_data("encrypted AES key")
            iv = self.receive_data("IV")

            # Decrypting AES key
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256()),
                    label=None
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
            return data

    def unpad(self, data):
        # PKCS#7 unpadding
        pad_len = data[-1]
        return data[:-pad_len]

def login():
    username = entry_username.get()
    if client.register(username):
        messagebox.showinfo("Successful", "Login successful")
        frame_login.pack_forget()
        frame_main.pack(pady=20, padx=20)
    else:
        messagebox.showerror("Error", "Login failed")

def post_image():
    image_path = entry_image_path.get()
    if image_path:
        client.post_image(image_path)
        messagebox.showinfo("Successful", "Image uploaded successfully")

def download_image():
    image_name = entry_image_name.get()
    if image_name:
        client.download_image(image_name)
        messagebox.showinfo("Successful", "Image downloaded successfully")

def start_gui():
    global entry_username, frame_login, frame_main, entry_image_path, entry_image_name
    root = tk.Tk()
    root.title("Secure Image Sharing Client")
    root.configure(bg="#e7ffa9")

    frame_login = tk.Frame(root, bg="#8f82b7")
    frame_login.pack(pady=20, padx=20)

    frame_main = tk.Frame(root, bg="#8f82b7")

    label_style = {"bg": "#e7ffa9", "fg": "#e28352", "font": ("Arial", 14)}
    entry_style = {"font": ("Arial", 14), "width": 30}
    button_style = {"font": ("Arial", 14), "width": 15}

    # Entry Frame
    tk.Label(frame_login, text="User Name:", **label_style).grid(row=0, column=0, padx=5, pady=10, sticky="e")
    entry_username = tk.Entry(frame_login, **entry_style)
    entry_username.grid(row=0, column=1, padx=5, pady=10)

    btn_login = tk.Button(frame_login, text="Login", command=login, bg="#ba617f", fg="white", **button_style)
    btn_login.grid(row=1, column=0, columnspan=2, pady=10)

    # Main Frame
    tk.Label(frame_main, text="Image Path:", **label_style).grid(row=0, column=0, padx=5, pady=10, sticky="e")
    entry_image_path = tk.Entry(frame_main, **entry_style)
    entry_image_path.grid(row=0, column=1, padx=5, pady=10)

    btn_post_image = tk.Button(frame_main, text="Upload Image", command=post_image, bg="#ba617f", fg="white", **button_style)
    btn_post_image.grid(row=1, column=0, columnspan=2, pady=10)

    tk.Label(frame_main, text="Image Name:", **label_style).grid(row=2, column=0, padx=5, pady=10, sticky="e")
    entry_image_name = tk.Entry(frame_main, **entry_style)
    entry_image_name.grid(row=2, column=1, padx=5, pady=10)

    btn_download_image = tk.Button(frame_main, text="Download Image", command=download_image, bg="#ba617f", fg="white", **button_style)
    btn_download_image.grid(row=3, column=0, columnspan=2, pady=10)

    root.mainloop()

if __name__ == '__main__':
    client = Client()
    start_gui()

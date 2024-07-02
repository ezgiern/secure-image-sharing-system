import socket
import threading
from utils import load_private_key, load_public_key, deserialize_public_key

class Server:
    def __init__(self, host='localhost', port=12345):
        # Creating the server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connecting the server socket to the specified address and port
        self.server_socket.bind((host, port))
        # Starting listening to the server socket
        self.server_socket.listen(5)
        # Where users and images will be stored
        self.clients = {}
        self.images = {}
        # Installing key pairs for the server
        self.server_public_key, self.server_private_key = self.load_keys()
        # Tracking online users
        self.online_users = {}

    def load_keys(self):
        # Loading the private and public keys for the server
        private_key = load_private_key('server_private_key.pem')
        public_key = load_public_key('server_public_key.pem')
        return public_key, private_key

    def handle_client(self, client_socket, addr):
        username = None
        try:
            while True:
                # Receiving the message from the client
                message = client_socket.recv(4096).decode('utf-8')
                if not message:
                    break
                print(f'{addr} message received from: {message}')
                
                #User registration process
                if message.startswith('REGISTER'):
                    parts = message.split(maxsplit=2)
                    username = parts[1]
                    user_public_key_pem = parts[2]
                    user_public_key = deserialize_public_key(user_public_key_pem.encode('utf-8'))
                    self.clients[username] = user_public_key
                    self.online_users[username] = client_socket  # Marking the user online
                    print(f"{username} saved, public key: {user_public_key_pem}")
                    client_socket.send(f'REGISTERED {username}'.encode('utf-8'))
                
                # The process of uploading images
                elif message.startswith('POST_IMAGE'):
                    parts = message.split(maxsplit=1)
                    image_name = parts[1]
                    print(f"Image name: {image_name}")
                    client_socket.send('ACK'.encode('utf-8'))

                    # Retrieving the encrypted image, signature, encrypted AES key and IV from the client
                    encrypted_image = self.receive_data(client_socket, "encrypted image")
                    signature = self.receive_data(client_socket, "signature")
                    encrypted_aes_key = self.receive_data(client_socket, "encrypted AES key")
                    iv = self.receive_data(client_socket, "IV")

                    # Storing images
                    self.images[image_name] = {
                        'encrypted_image': encrypted_image,
                        'signature': signature,
                        'encrypted_aes_key': encrypted_aes_key,
                        'iv': iv,
                        'owner': username
                    }
                    print(f"{image_name} image has been retrieved and stored.")

                    # Sending notifications to all online users
                    self.notify_users(f'NEW_IMAGE {image_name} {username}')
                
                # Downloading images
                elif message.startswith('DOWNLOAD'):
                    parts = message.split(maxsplit=1)
                    image_name = parts[1]
                    print(f"Received image request to download: {image_name}")
                    if image_name in self.images:
                        image_info = self.images[image_name]
                        client_socket.send(f'SENDING_IMAGE {image_name}'.encode('utf-8'))
                        self.send_data(client_socket, image_info['encrypted_image'], "encrypted image")
                        self.send_data(client_socket, image_info['signature'], "signature")
                        self.send_data(client_socket, image_info['encrypted_aes_key'], "encrypted AES key")
                        self.send_data(client_socket, image_info['iv'], "IV")
                    else:
                        client_socket.send(f'IMAGE_NOT_FOUND {image_name}'.encode('utf-8'))
        except Exception as e:
            print(f"An error occurred at {addr} address: {e}")
        finally:
            if username:
                self.online_users.pop(username, None)
            client_socket.close()

    def receive_data(self, client_socket, data_type):
      # Receiving data from the client
        header = client_socket.recv(4096).decode('utf-8')
        if data_type in header:
            client_socket.send('ACK'.encode('utf-8'))
            data_length = int(header.split()[-1])
            data = b''
            while len(data) < data_length:
                data += client_socket.recv(data_length - len(data))
            print(f"{data_type} received, length: {len(data)}")
            return data

    def send_data(self, client_socket, data, data_type):
       # Sending data to the client
        data_length = len(data)
        client_socket.send(f'{data_type} {data_length}'.encode('utf-8'))
        ack = client_socket.recv(4096).decode('utf-8')
        if ack == 'ACK':
            client_socket.send(data)
            print(f"{data_type} sent")

    def notify_users(self, message):
        # Sending notifications to users
        print(f"Notifications are being sent to users: {message}")
        for user, sock in self.online_users.items():
            try:
                sock.send(message.encode('utf-8'))
                print(f"{user} notified")
            except Exception as e:
                print(f"An error occurred while reporting{user}: {e}")

    def start(self):
        # Staring server
        print("Sunucu başlatıldı.")
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been accepted")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            client_handler.start()

if __name__ == '__main__':
    server = Server()
    server.start()


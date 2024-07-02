# Image Sharing System

## Group Members
Ezgi Eren
150119515

## Project Description
In this project, we have tried to implement a secure image sharing system with various security features to ensure the confidentiality, integrity and accuracy of images shared between users.

## Design Choices

### Generation and Storage of The Keys
- **RSA Key Pair**: Both the server and the clients generate RSA key pairs. The server's public key is distributed to all clients, and each client's public key is saved to the server.

### Registration and Certification of Public Keys 
- **User Registration**: Users register on the server by submitting their username and public keys. The server signs this key and creates a certificate, stores the certificate and sends a copy to the user.


### Image Posting
- **AES Encryption**: The images are encrypted in CBC mode with a randomly generated AES key and IV. The AES key is then encrypted with the server's public key.
- **Digital Signatures**: To ensure the accuracy of the image, it is signed using the users' private key and the SHA256 hash function.
- **Data Transmission**: The encrypted image, digital signature, encrypted AES key and IV are sent to the server and stored.

### Image Downloading
- **Request and Response**: Users can request images by their name. The server sends a response containing an encrypted image, a digital signature, and the client's public key, as well as an encrypted AES key.
- **Decryption and Verification**: Users decode the AES key with their private keys, decode the image, and verify the digital signature to ensure integrity and accuracy.

### Notifications
- **New Image Notification**: When a new image is uploaded, the server sends a notification with the image name and the owner's name to all users who are online.

## Security Features
- **Privacy**: The images are encrypted with AES before being sent to the server, which ensures that only authorized users can see the content.
- **Integrity**: Digital signatures are used to verify that images have not been altered.
- **Authentication**: The use of public key certificates allows users to verify who they are.

## Potential Vulnerabilities and Countermeasures

### Potential Security Holes
1. **Key Management**: If the private keys are not stored securely, they can be intercepted.
2. **Man-in-the-Middle Attacks**: If the initial key exchange is not secure, an attacker can capture and exchange the keys.
3. **Replay Attacks**: Without proper mechanisms, attackers can disrupt the system by resending old messages.

### Countermeasures
1. **Secure Storage**: Private keys must be stored securely using hardware security modules (HSMs) or encrypted storage solutions.
2. **Secure Key Exchange**: The implementation of secure key exchange protocols such as Diffie-Hellman or the use of TLS for all communications can prevent man-in-the-middle attacks.
3. **Time Stamps and Numerical Signs**: Adding timestamps or numeric marks to messages can prevent replay attacks by verifying that messages are fresh and not being reused.

## How To Run
1. Make sure that the necessary Python libraries are installed. You can install the dependencies using the following command:
    ```sh
    pip install -r requirements.txt
    ```

2. Generate keys:
    ```sh
    python utils.py
    ```

3. Start the server:
    ```sh
    python server.py
    ```

4. Launch the client (with GUI):
    ```sh
    python client_gui.py
    ```



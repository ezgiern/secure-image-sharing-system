from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_fixed_key_pair():
    """Create a fixed RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair(private_key, public_key, private_key_filename, public_key_filename):
    """Save the private and public key pair to files."""
    with open(private_key_filename, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_filename, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(filename):
    """Upload the private key from a file."""
    with open(filename, 'rb') as f:
        private_key_pem = f.read()
    return serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

def load_public_key(filename):
    """Upload the public key from a file."""
    with open(filename, 'rb') as f:
        public_key_pem = f.read()
    return serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

def serialize_public_key(public_key):
    """Serialize the public key into PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_pem):
    """Serialize a public key in PEM format."""
    return serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

def deserialize_private_key(private_key_pem):
    """Serialize a private key in PEM format."""
    return serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

def pad(data, block_size):
    """Fill in the data according to the block size (pad)."""
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length]) * padding_length

def unpad(data, block_size):
    """Extract padding (pad) bytes from the data."""
    padding_length = data[-1]
    return data[:-padding_length]

if __name__ == "__main__":
    # Create fixed key pairs
    private_key, public_key = generate_fixed_key_pair()

    # Save the same key pair for the server
    save_key_pair(private_key, public_key, 'server_private_key.pem', 'server_public_key.pem')

    # Save the same key pair for the client
    save_key_pair(private_key, public_key, 'ezgi_private_key.pem', 'ezgi_public_key.pem')

    print("Fixed RSA key pairs have been created and 'server_private_key.pem', 'server_public_key.pem', 'ezgi_private_key.pem' and 'ezgi_public_key.it was saved to the 'pem' files.")







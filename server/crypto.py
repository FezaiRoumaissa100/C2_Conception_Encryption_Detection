import base64, os, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Shared AES-256 key (32 bytes)
# The same key must be in the agent!
KEY = bytes.fromhex(
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)

def encrypt(data: dict) -> str:
    """Encrypts a dictionary with AES-256-GCM"""
    data_bytes = json.dumps(data).encode()
    nonce = os.urandom(12)
    cipher = AESGCM(KEY)
    encrypted = cipher.encrypt(nonce, data_bytes, None)
    return base64.b64encode(nonce + encrypted).decode()

def decrypt(data_b64: str) -> dict:
    """Decrypts an AES-256-GCM message"""
    data = base64.b64decode(data_b64)
    nonce = data[:12]
    encrypted = data[12:]
    cipher = AESGCM(KEY)
    decrypted = cipher.decrypt(nonce, encrypted, None)
    return json.loads(decrypted)

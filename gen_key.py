# save this as gen_key.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64

# generate keypair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# export public key as base64
pub_raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
pub_b64 = base64.b64encode(pub_raw).decode()

print("Public key (base64):", pub_b64)

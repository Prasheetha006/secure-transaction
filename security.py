# utils.py (or security.py)

import base64, os, time, json, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# ✅ Generate a new Ed25519 keypair
def generate_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

# ✅ Export public key as base64 string
def export_public_key_b64(public_key):
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    ).decode("utf-8")

# ✅ Export private key as base64 string
def export_private_key_b64(private_key):
    return base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    ).decode("utf-8")

# ✅ Load private key from base64
def load_private_key_b64(priv_b64: str):
    raw = base64.b64decode(priv_b64)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

# ✅ Canonical JSON encoder (stable ordering + no spaces)
def canonical_json(data) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode()

# ✅ Build message to sign
def message_to_sign(tx_body: dict, nonce: str, ts: int, idem_key: str) -> bytes:
    digest = hashlib.sha256(canonical_json(tx_body)).hexdigest()
    msg = {
        "version": "v1",
        "digest": digest,
        "nonce": nonce,
        "ts": ts,
        "idempotency_key": idem_key
    }
    return canonical_json(msg)

# ✅ Sign a message
def sign(private_key, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("utf-8")

# ✅ Generate unique nonce
def new_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")

# ✅ Current timestamp
def now_ts() -> int:
    return int(time.time())

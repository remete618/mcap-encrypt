"""mcap-encrypt: chunk-level encryption for MCAP robotics data files.

Public API:
    generate_key_pair()         -> (pub_pem, priv_pem)   RSA-4096
    generate_x25519_key_pair()  -> (pub_pem, priv_pem)   X25519
    encrypt_mcap(input, keys)   -> bytes
    decrypt_mcap(input, key)    -> bytes
    iterate_messages(input, key) -> Iterator[dict]
    inspect_mcap(input)         -> InspectResult
    rotate_mcap_keys(input, old_priv, new_pubs) -> bytes
"""

from ._keys import generate_key_pair, generate_x25519_key_pair
from .decrypt import decrypt_mcap, iterate_messages
from .encrypt import encrypt_mcap
from .inspect import InspectResult, RecipientInfo, inspect_mcap
from .rotate import rotate_mcap_keys

__all__ = [
    "generate_key_pair",
    "generate_x25519_key_pair",
    "encrypt_mcap",
    "decrypt_mcap",
    "iterate_messages",
    "inspect_mcap",
    "InspectResult",
    "RecipientInfo",
    "rotate_mcap_keys",
]

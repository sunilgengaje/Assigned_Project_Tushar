# Simple in-memory AES key store for demonstration (use Redis or DB in production)
from typing import Dict
from threading import Lock

class AESKeyStore:
    def __init__(self):
        self._store: Dict[str, bytes] = {}
        self._lock = Lock()

    def set_key(self, username: str, key: bytes):
        with self._lock:
            self._store[username] = key

    def get_key(self, username: str) -> bytes:
        with self._lock:
            return self._store.get(username)

aes_key_store = AESKeyStore()

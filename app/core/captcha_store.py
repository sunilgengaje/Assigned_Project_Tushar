# app/core/captcha_store.py
import uuid

class CaptchaStore:
    def __init__(self):
        self._store = {}
    def set(self, captcha_id, solution):
        self._store[captcha_id] = solution
    def get(self, captcha_id):
        return self._store.get(captcha_id)
    def delete(self, captcha_id):
        if captcha_id in self._store:
            del self._store[captcha_id]

captcha_store = CaptchaStore()

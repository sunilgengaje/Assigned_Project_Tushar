
import os
import json

class APILogger:
    """
    API Logger that prints logs only in DEV and UAT environments.
    Usage:
        logger = APILogger()
        logger.log("Some debug info")
    """
    def __init__(self):
        self.env = os.getenv("API_ENV", "DEV").upper()
        # Disable logging in PROD
        self.enabled = self.env in ("DEV", "UAT")

    def log(self, *args, **kwargs):
        if self.enabled:
            print("[API LOG]", *args, **kwargs)

    def log_request_payload(self, payload, endpoint=None):
        if self.enabled:
            if isinstance(payload, (dict, list)):
                pretty = json.dumps(payload, indent=2, ensure_ascii=False)
            else:
                pretty = str(payload)
            msg = f"[REQUEST PAYLOAD]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            print(msg)

    def log_encrypted_response(self, encrypted, endpoint=None):
        if self.enabled:
            if isinstance(encrypted, (dict, list)):
                pretty = json.dumps(encrypted, indent=2, ensure_ascii=False)
            else:
                pretty = str(encrypted)
            msg = f"[ENCRYPTED RESPONSE]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            print(msg)

    def log_decrypted_response(self, decrypted, endpoint=None):
        if self.enabled:
            if isinstance(decrypted, (dict, list)):
                pretty = json.dumps(decrypted, indent=2, ensure_ascii=False)
            else:
                pretty = str(decrypted)
            msg = f"[DECRYPTED RESPONSE]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            print(msg)

# Example usage:
# logger = APILogger()
# logger.log("This will print only in DEV or UAT")

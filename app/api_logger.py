

import os
import json
import logging


class APILogger:
    """
    API Logger that prints logs only in DEV and UAT environments.
    Logs to both stdout and error.log.
    Usage:
        logger = APILogger()
        logger.log("Some debug info")
    """
    def __init__(self):
        self.env = os.getenv("API_ENV", "DEV").upper()
        # Disable logging in PROD
        self.enabled = self.env in ("DEV", "UAT")

        self.logger = logging.getLogger("api_logger")
        self.logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers if re-imported
        if not self.logger.handlers:
            formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            # File handler
            file_handler = logging.FileHandler("error.log")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            # Stream handler (stdout)
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.DEBUG)
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

    def log(self, *args, **kwargs):
        if self.enabled:
            msg = " ".join(str(a) for a in args)
            self.logger.info(msg)

    def log_request_payload(self, payload, endpoint=None):
        if self.enabled:
            if isinstance(payload, (dict, list)):
                pretty = json.dumps(payload, indent=2, ensure_ascii=False)
            else:
                pretty = str(payload)
            msg = f"[REQUEST PAYLOAD]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            self.logger.info(msg)

    def log_encrypted_response(self, encrypted, endpoint=None):
        if self.enabled:
            if isinstance(encrypted, (dict, list)):
                pretty = json.dumps(encrypted, indent=2, ensure_ascii=False)
            else:
                pretty = str(encrypted)
            msg = f"[ENCRYPTED RESPONSE]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            self.logger.info(msg)

    def log_decrypted_response(self, decrypted, endpoint=None):
        if self.enabled:
            if isinstance(decrypted, (dict, list)):
                pretty = json.dumps(decrypted, indent=2, ensure_ascii=False)
            else:
                pretty = str(decrypted)
            msg = f"[DECRYPTED RESPONSE]{' [' + endpoint + ']' if endpoint else ''}:\n{pretty}"
            self.logger.info(msg)

# Example usage:
# logger = APILogger()
# logger.log("This will print only in DEV or UAT")

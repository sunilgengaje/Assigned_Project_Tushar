import requests
import base64
import json

BASE_URL = "http://localhost:8000/api/unlock-user"
EMAIL = "sunygengaje@yahoo.com"  # Replace with the email to unlock


headers = {
    "Content-Type": "application/json"
}

data = {
    "email": "sunygengaje@yahoo.com"  # The backend now expects 'email' only
}

response = requests.post(BASE_URL, json=data, headers=headers)
resp_json = response.json()

# If error is base64-encoded, decode it
if "error" in resp_json:
    error_decoded = base64.b64decode(resp_json["error"]).decode()
    print("Error:", error_decoded)
else:
    print("Success:", resp_json)

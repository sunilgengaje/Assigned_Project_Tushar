import requests
import base64
import json

BASE_URL = "http://localhost:8000/api/add-manage-aggregator-encrypted"

# User data to send (replace with actual values)
user_data = {
    "aggregatorName": "Test Aggregator",
    "contactPersonName": "Test Person",
    "email": "sunygengaje@gmail.com",
    "mobileNo": "1234567890",
    "location": "Test City",
    "services": "Test Service"
}

# Encode user data as base64 JSON
user_json = json.dumps(user_data, separators=(",", ":")).encode()
data_b64 = base64.b64encode(user_json).decode()

payload = {
    "data": data_b64
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(BASE_URL, json=payload, headers=headers)
try:
    resp_json = response.json()
except Exception:
    print("Raw response:", response.text)
    raise

# Decode base64 'data' field if present
if "data" in resp_json:
    try:
        decoded = base64.b64decode(resp_json["data"]).decode()
        data_json = json.loads(decoded)
    except Exception as e:
        print("Failed to decode base64 response:", e)
        print("Raw response:", resp_json)
        raise
    if data_json.get("flag") == "F":
        print("Error:", data_json.get("message"))
    else:
        print("Success:", data_json)
else:
    print("Unexpected response format:", resp_json)

import requests
import json
from base64 import b64encode

API_URL = "http://localhost:8000/api/manage-aggregator/reset-password"

def encode_payload(payload: dict) -> str:
    json_str = json.dumps(payload)
    return b64encode(json_str.encode()).decode()

def validate_temp_password(email, temp_password, mobile_no):
    payload = {
        "email": email,
        "temporary_password": temp_password,
        "mobileNo": mobile_no,
        "validate_only": True
    }
    encoded = encode_payload(payload)
    resp = requests.post(API_URL, json={"data": encoded})
    print("Validation Response:", resp.status_code, resp.json())

def reset_password(email, temp_password, mobile_no, new_password):
    payload = {
        "email": email,
        "temporary_password": temp_password,
        "mobileNo": mobile_no,
        "new_password": new_password
    }
    encoded = encode_payload(payload)
    resp = requests.post(API_URL, json={"data": encoded})
    print("Reset Response:", resp.status_code, resp.json())

if __name__ == "__main__":
    # Fill these with actual values for testing
    email = "your_email@example.com"
    temp_password = "TEMP_PASSWORD_FROM_EMAIL"
    mobile_no = "YOUR_MOBILE_NUMBER"
    new_password = "NewSecurePassword123"

    # Step 1: Validate temporary password
    validate_temp_password(email, temp_password, mobile_no)

    # Step 2: Reset password
    reset_password(email, temp_password, mobile_no, new_password)
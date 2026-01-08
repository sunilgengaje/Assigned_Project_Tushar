import requests
import json
import base64

API_URL = "http://localhost:8000/api/manage-aggregator/reset-password-plain"

def encode_payload(payload: dict) -> str:
    json_str = json.dumps(payload)
    return base64.b64encode(json_str.encode()).decode()

def decode_response(data: str) -> dict:
    decoded = base64.b64decode(data).decode()
    return json.loads(decoded)

def reset_password(email, mobile_no, temp_password, new_password, confirm_password):
    payload = {
        "email": email,
        "mobileNo": mobile_no,
        "temporary_password": temp_password,
        "new_password": new_password,
        "confirm_password": confirm_password
    }
    encoded = encode_payload(payload)
    resp = requests.post(API_URL, json={"data": encoded})
    print("Status Code:", resp.status_code)
    try:
        data = resp.json().get("data")
        if data:
            print("Decoded Response:", decode_response(data))
        else:
            print("Raw Response:", resp.text)
    except Exception as e:
        print("Error decoding response:", e)
        print("Raw Response:", resp.text)

if __name__ == "__main__":
    # Fill these with actual values for testing
    email = "your_email@example.com"
    mobile_no = "YOUR_MOBILE_NUMBER"
    temp_password = "TEMP_PASSWORD_FROM_EMAIL"
    new_password = "YourNewPassword123"
    confirm_password = "YourNewPassword123"

    reset_password(email, mobile_no, temp_password, new_password, confirm_password)

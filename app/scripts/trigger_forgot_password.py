import requests
import base64
import json

# Update these values as needed
BACKEND_URL = "http://localhost:8000/api/forgot-password"
EMAIL = "sunygengaje@gmail.com"
MOBILE_NO = "1234567890"  # Replace with the correct mobile number

def trigger_forgot_password(email, mobile_no):
    payload = {"email": email, "mobileNo": mobile_no}
    data_b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    req_body = {"data": data_b64}
    resp = requests.post(BACKEND_URL, json=req_body)
    if resp.status_code == 200:
        # The backend does not return the password, it is sent via email
        print("Forgot password request successful. Check your email for the new password.")
    else:
        print(f"Request failed: {resp.status_code}")
        try:
            print(resp.json())
        except Exception:
            print(resp.text)

if __name__ == "__main__":
    trigger_forgot_password(EMAIL, MOBILE_NO)

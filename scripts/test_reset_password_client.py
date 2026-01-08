import requests
import base64
import json

def main():
    url = "http://localhost:8000/api/manage-aggregator/reset-password-plain"
    email = input("Enter email: ")
    flag = input("Enter flag (should be 'S' if validated): ")
    newpassword = input("Enter new password: ")

    payload = {
        "email": "sunygengaje@yahoo.com",
        "flag": "S",
        "newpassword": "Sunil@123"
    }
    encoded_data = base64.b64encode(json.dumps(payload).encode()).decode()
    req_body = {"data": encoded_data}

    response = requests.post(url, json=req_body)
    if response.status_code == 200:
        try:
            resp_data = response.json().get("data")
            decoded = base64.b64decode(resp_data).decode()
            print("Response:", decoded)
        except Exception as e:
            print("Error decoding response:", e)
            print("Raw response:", response.text)
    else:
        print(f"HTTP {response.status_code}: {response.text}")

if __name__ == "__main__":
    main()

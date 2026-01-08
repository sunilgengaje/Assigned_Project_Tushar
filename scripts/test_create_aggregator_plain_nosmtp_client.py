import requests
import json

def main():
    url = "http://localhost:8000/api/manage-aggregator/plain-nosmtp"
    print("Enter aggregator details to create (no SMTP, plain JSON response):")
    aggregatorName = input("Aggregator Name: ")
    contactPersonName = input("Contact Person Name: ")
    email = input("Email: ")
    mobileNo = input("Mobile No: ")
    location = input("Location: ")
    services = input("Services: ")

    payload = {
        "aggregatorName": aggregatorName,
        "contactPersonName": contactPersonName,
        "email": email,
        "mobileNo": mobileNo,
        "location": location,
        "services": services
    }

    response = requests.post(url, json=payload)
    print(f"Status: {response.status_code}")
    try:
        print("Response:", response.json())
    except Exception:
        print("Raw response:", response.text)

if __name__ == "__main__":
    main()

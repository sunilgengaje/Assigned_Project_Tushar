import requests
import tempfile
from PIL import Image

BASE_URL = "http://localhost:8000"

if __name__ == "__main__":
    print("Fetching captcha...")
    resp = requests.get(f"{BASE_URL}/auth/captcha")
    captcha_id = resp.headers.get("X-Captcha-Id")
    print("Captcha ID:", captcha_id)
    # Save captcha image to temp file and open
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp.write(resp.content)
        tmp_path = tmp.name
    print(f"Captcha image saved to: {tmp_path}")
    try:
        Image.open(tmp_path).show()
    except Exception:
        print("Open the captcha image manually to view.")
    # User can now enter the solution after viewing the image
    captcha_solution = input("Enter captcha shown in image: ").strip()
    print(f"You entered: {captcha_solution}")
    # You can now use captcha_id and captcha_solution for login

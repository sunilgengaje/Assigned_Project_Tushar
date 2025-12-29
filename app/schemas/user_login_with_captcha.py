from pydantic import BaseModel

class UserLoginWithCaptcha(BaseModel):
    username: str
    password: str
    captcha_id: str
    captcha_solution: str

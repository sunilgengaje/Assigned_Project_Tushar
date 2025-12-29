from fastapi.responses import JSONResponse
from app.schemas.response import SuccessResponse, ErrorResponse

def success_response(message: str, data=None, status_code=200):
    return JSONResponse(
        status_code=status_code,
        content=SuccessResponse(message=message, data=data).dict()
    )

def error_response(message: str, error_code: str, details=None, status_code=400):
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(message=message, error_code=error_code, details=details).dict()
    )

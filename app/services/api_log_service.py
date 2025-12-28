import base64
from datetime import datetime
from app.models.api_log import APILog

def log_api_entry(db, username, client_ip, api_endpoint, request_data, accessed_key_bytes, status_flag, session_id=None):
    """
    Log an API call to the api_logs table.
    accessed_key_bytes: AES key as bytes (will be base64-encoded)
    status_flag: 'S' for success, 'F' for failure
    """
    accessed_key_b64 = base64.b64encode(accessed_key_bytes).decode() if accessed_key_bytes else None
    log_entry = APILog(
        username=username,
        client_ip=client_ip,
        api_endpoint=api_endpoint,
        request_data=request_data,
        access_time=datetime.utcnow(),
        accessed_key=accessed_key_b64,
        status=status_flag,
        session_id=session_id
    )
    db.add(log_entry)
    db.commit()

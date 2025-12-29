import redis
import os
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

BLACKLIST_PREFIX = "jwt_blacklist:"

def blacklist_token(jti: str, exp_timestamp: int):
    ttl = exp_timestamp - int(__import__('time').time())
    if ttl > 0:
        redis_client.setex(BLACKLIST_PREFIX + jti, ttl, "1")

def is_token_blacklisted(jti: str) -> bool:
    try:
        return redis_client.exists(BLACKLIST_PREFIX + jti) == 1
    except Exception as e:
        # Log the error and treat as not blacklisted (allow access), or optionally raise a custom error
        import sys
        print(f"[REDIS ERROR] Could not check JWT blacklist: {e}", file=sys.stderr)
        # Option 1: Allow access if Redis is down (comment out next line to allow)
        # return False
        # Option 2: Deny access if Redis is down (uncomment next line to deny)
        # raise RuntimeError("Redis unavailable for JWT blacklist check")
        # Option 3: Return a special value to signal Redis is down
        raise Exception("Redis unavailable for JWT blacklist check")

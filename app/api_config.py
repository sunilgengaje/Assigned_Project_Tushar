import os
from dotenv import load_dotenv

class APIConfig:
    """Loads and stores API base URL and endpoints from .env and constants."""
    def __init__(self, env_path=None):
        """
        Loads API base URL and endpoints from .env. Supports dynamic environment selection (DEV, UAT, PROD) via API_ENV variable.
        WARNING: Never log or print this object directly in production.
        """
        if env_path is None:
            env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "../.env")
        load_dotenv(dotenv_path=env_path)
        api_env = os.getenv("API_ENV", "DEV").upper()
        # Resolve base URL at runtime to avoid exposing mapping in code
        def resolve_base_url(env):
            env_var_map = {
                "DEV": "API_URL_DEV",
                "UAT": "API_URL_UAT",
                "PROD": "API_URL_PROD"
            }
            var_name = env_var_map.get(env, "API_URL_DEV")
            url = os.getenv(var_name)
            if not url:
                raise ValueError(f"Environment variable {var_name} must be set for {env} environment. No default is provided.")
            return url
        self.base_url = resolve_base_url(api_env).rstrip("/")
        # Validate base_url (basic check)
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            raise ValueError("API_URL in .env must start with http:// or https://")
        # Define endpoints here (do not store secrets)
        self.LOGIN = f"{self.base_url}/auth/login"
        self.PROJECTIONS = lambda app_id, agg_id: f"{self.base_url}/auth/api/applications/{app_id}/aggregators/{agg_id}/projections"
        # Add more endpoints as needed

    def get_safe_endpoints(self):
        """Return a dict of safe (non-secret) endpoints for diagnostics."""
        return {
            "LOGIN": self.LOGIN,
            "PROJECTIONS": self.PROJECTIONS('<app_id>', '<agg_id>')
        }

    def __repr__(self):
        # Never print secrets or sensitive config
        return "<APIConfig: endpoints loaded, base_url hidden>"

# Usage example:
# config = APIConfig()
# print(config.LOGIN)
# print(config.PROJECTIONS(1, 2))

import os
from dotenv import load_dotenv

load_dotenv()

def get_env(key, default=None):
    """Read an environment variable, fallback to default if missing."""
    return os.getenv(key, default)
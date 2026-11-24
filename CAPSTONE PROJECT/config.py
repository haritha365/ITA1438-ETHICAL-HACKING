import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'sentinel_shield_adaptive_auth_super_secret_2026')
    
    # MySQL Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'adaptive_auth_db')
    DB_PORT = int(os.getenv('DB_PORT', 3306))

    # Adaptive Security Engine Default Parameters
    DEFAULT_MAX_FAILED_ATTEMPTS = 5
    DEFAULT_WINDOW_MINUTES = 5
    DEFAULT_LOCKOUT_MINUTES = 10
    DEFAULT_SUSPICIOUS_THRESHOLD = 50
    DEFAULT_CAPTCHA_THRESHOLD = 3
    DEFAULT_AUTO_BLOCK_IP = True
    DEFAULT_IP_BLOCK_THRESHOLD = 8
    DEFAULT_IP_BLOCK_MINUTES = 60


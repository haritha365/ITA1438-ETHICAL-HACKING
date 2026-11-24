from backend.security.adaptive_engine import adaptive_engine
from backend.security.hasher import password_service
from backend.security.captcha_service import captcha_service

# Backward-compatibility wrapper for legacy references
class SecurityEngineProxy:
    def hash_password(self, password: str) -> str:
        return password_service.hash_password(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return password_service.verify_password(plain, hashed)

    def evaluate_pre_login(self, username: str, ip: str, ua: str = ''):
        return adaptive_engine.evaluate_pre_login(username, ip, ua)

    def process_failed_attempt(self, username: str, ip: str, ua: str, reason: str):
        return adaptive_engine.process_failed_attempt(username, ip, ua, reason)

    def process_successful_attempt(self, user: dict, ip: str, ua: str):
        return adaptive_engine.process_successful_attempt(user, ip, ua)

    def unlock_user_account(self, user_id: int, unlocked_by: str = "Admin"):
        return adaptive_engine.unlock_user_account(user_id, unlocked_by)

    def generate_captcha_token(self, identifier: str) -> dict:
        return captcha_service.generate_challenge(identifier)

    def verify_captcha_token(self, identifier: str, user_input: str) -> bool:
        return captcha_service.verify_challenge(identifier, user_input)

    def get_settings(self):
        return adaptive_engine.get_settings()

    def update_settings(self, s: dict):
        return adaptive_engine.update_settings(s)

security_engine = SecurityEngineProxy()

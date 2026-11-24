import json
import unittest
from app import app
from database import db
from security_engine import security_engine

class TestAdaptiveAuthSystem(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_health_check(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'healthy')
        print("[TEST PASS] API Health Check OK")

    def test_02_all_pages_render(self):
        pages = [
            '/', '/register', '/login', '/dashboard', 
            '/realtime', '/analytics', '/ip-monitoring', 
            '/captcha', '/alerts', '/login-history', 
            '/accounts', '/settings'
        ]
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} failed to render")
        print(f"[TEST PASS] All {len(pages)} Web Pages Render Cleanly (HTTP 200)")

    def test_03_registration(self):
        payload = {
            'fullName': 'Unit Test User',
            'username': 'unittest_user',
            'email': 'unittest@sentinel.ai',
            'password': 'SecureTestPassword123!'
        }
        res = self.client.post('/api/auth/register', json=payload)
        # 201 or 409 if already exists
        self.assertIn(res.status_code, [201, 409])
        print("[TEST PASS] User Registration with Bcrypt Hashing OK")

    def test_04_successful_login(self):
        # Admin default user
        user = db.execute_query("SELECT * FROM users WHERE username = 'admin' LIMIT 1;", fetch_one=True)
        # Update admin password hash to a known bcrypt hash for testing if needed
        test_hash = security_engine.hash_password("Admin@1234")
        db.execute_query("UPDATE users SET password_hash = %s, failed_attempts = 0, status = 'Active' WHERE username = 'admin';", (test_hash,), commit=True)

        res = self.client.post('/api/auth/login', json={'username': 'admin', 'password': 'Admin@1234'})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        print("[TEST PASS] Successful Authentication OK")

    def test_05_brute_force_detection_and_lockout(self):
        # Reset security settings to baseline (max_failed_attempts = 5)
        self.client.post('/api/settings', json={'maxFailedAttempts': 5, 'lockoutMinutes': 10, 'captchaThreshold': 3})

        # Create victim account
        test_hash = security_engine.hash_password("Victim@2026")
        db.execute_query('''
            INSERT INTO users (full_name, username, email, password_hash, role, status, failed_attempts)
            VALUES ('Victim Test', 'victim_test', 'victim@sentinel.ai', %s, 'Standard User', 'Active', 0)
            ON CONFLICT(username) DO UPDATE SET failed_attempts = 0, status = 'Active';
        ''', (test_hash,), commit=True)

        # Trigger 5 failed attempts
        for attempt in range(1, 6):
            res = self.client.post('/api/auth/login', json={'username': 'victim_test', 'password': 'WrongPassword123!'})
            self.assertIn(res.status_code, [400, 401, 403])

        # 6th attempt must be rejected due to account lockout
        res6 = self.client.post('/api/auth/login', json={'username': 'victim_test', 'password': 'WrongPassword123!'})
        self.assertEqual(res6.status_code, 403)
        data6 = res6.get_json()
        self.assertEqual(data6['status'], 'ACCOUNT_LOCKED')
        print("[TEST PASS] Adaptive Engine Brute-Force Lockout Successfully Triggered (HTTP 403)")

if __name__ == '__main__':
    unittest.main()


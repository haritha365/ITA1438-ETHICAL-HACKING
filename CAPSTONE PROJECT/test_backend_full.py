import unittest
import json
from app import app
from backend.database.connection import db_manager

class TestFullBackendSuite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_health_and_headers(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(res.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(res.headers.get('X-Frame-Options'), 'SAMEORIGIN')
        print("[PASS] Health Check & Security Headers")

    def test_02_dashboard_stats_and_charts(self):
        res = self.client.get('/api/dashboard/stats')
        self.assertEqual(res.status_code, 200)
        stats = res.get_json()
        self.assertIn('totalUsers', stats)
        self.assertIn('detectedAttacks', stats)

        res_charts = self.client.get('/api/dashboard/charts')
        self.assertEqual(res_charts.status_code, 200)
        charts = res_charts.get_json()
        self.assertIn('successVsFailed', charts)
        self.assertIn('topSuspiciousIps', charts)
        self.assertIn('threatDistribution', charts)

        res_act = self.client.get('/api/dashboard/activity')
        self.assertEqual(res_act.status_code, 200)

        res_alt = self.client.get('/api/dashboard/alerts')
        self.assertEqual(res_alt.status_code, 200)
        print("[PASS] Dashboard Stats, 5 Charts & Activity Feeds")

    def test_03_ip_monitoring_apis(self):
        # List IPs
        res = self.client.get('/api/ip-monitoring')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])

        # Block an IP
        block_res = self.client.post('/api/ip-monitoring/block', json={'ip': '198.51.100.99', 'reason': 'Test Probe'})
        self.assertEqual(block_res.status_code, 200)

        # Unblock the IP
        unblock_res = self.client.post('/api/ip-monitoring/unblock', json={'ip': '198.51.100.99'})
        self.assertEqual(unblock_res.status_code, 200)
        print("[PASS] IP Monitoring, Block & Unblock APIs")

    def test_04_alerts_management_apis(self):
        res = self.client.get('/api/alerts?severity=ALL')
        self.assertEqual(res.status_code, 200)
        alerts = res.get_json()['alerts']
        self.assertIsInstance(alerts, list)

        if alerts:
            first_id = alerts[0]['id']
            res_resolve = self.client.post(f'/api/alerts/{first_id}/resolve')
            self.assertEqual(res_resolve.status_code, 200)
        print("[PASS] Security Alerts Triage & Resolve APIs")

    def test_05_accounts_apis(self):
        # List accounts
        res = self.client.get('/api/accounts')
        self.assertEqual(res.status_code, 200)
        users = res.get_json()['users']
        self.assertGreaterEqual(len(users), 1)

        # Unlock user account
        res_unlock = self.client.post('/api/accounts/unlock', json={'username': 'finance_mgr'})
        self.assertEqual(res_unlock.status_code, 200)

        # Password reset
        res_reset = self.client.post('/api/accounts/reset-password', json={'username': 'demo'})
        self.assertEqual(res_reset.status_code, 200)
        print("[PASS] User Account Directory, 1-Click Unlock & Password Reset APIs")

    def test_06_analytics_apis(self):
        res_trends = self.client.get('/api/analytics/trends?range=7d')
        self.assertEqual(res_trends.status_code, 200)

        res_targets = self.client.get('/api/analytics/targeted-accounts')
        self.assertEqual(res_targets.status_code, 200)

        res_ips = self.client.get('/api/analytics/attacker-ips')
        self.assertEqual(res_ips.status_code, 200)

        res_exp_json = self.client.get('/api/analytics/export?format=json')
        self.assertEqual(res_exp_json.status_code, 200)

        res_exp_csv = self.client.get('/api/analytics/export?format=csv')
        self.assertEqual(res_exp_csv.status_code, 200)
        self.assertIn('text/csv', res_exp_csv.headers.get('Content-Type', ''))
        print("[PASS] Analytics Trends, Geolocation & Report Exports (JSON/CSV)")

    def test_07_settings_and_diagnostics_apis(self):
        res_get = self.client.get('/api/settings')
        self.assertEqual(res_get.status_code, 200)

        res_post = self.client.post('/api/settings', json={'maxFailedAttempts': 6, 'lockoutMinutes': 15})
        self.assertEqual(res_post.status_code, 200)

        res_diag = self.client.post('/api/settings/diagnostics')
        self.assertEqual(res_diag.status_code, 200)
        self.assertEqual(res_diag.get_json()['status'], '100% HEALTHY')
        print("[PASS] System Settings Management & Diagnostic APIs")

    def test_08_realtime_simulation_apis(self):
        # Single simulation
        res_sim = self.client.post('/api/realtime/simulate', json={'type': 'single_fail', 'username': 'admin'})
        self.assertEqual(res_sim.status_code, 200)

        # Wave simulation
        res_wave = self.client.post('/api/realtime/simulate', json={'type': 'wave', 'username': 'admin'})
        self.assertEqual(res_wave.status_code, 200)

        # Reset simulation
        res_rst = self.client.post('/api/realtime/simulate', json={'type': 'reset'})
        self.assertEqual(res_rst.status_code, 200)
        print("[PASS] Real-time Attack Simulation Engine (Single & Wave Probes)")

if __name__ == '__main__':
    unittest.main()


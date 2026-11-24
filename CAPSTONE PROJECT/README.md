# Adaptive Authentication Security System for Real-Time Brute-Force Attack Detection and Prevention

> **SentinelShield (AASS)** — An enterprise-grade, light-themed cybersecurity SaaS web platform built for real-time authentication risk calculation, adaptive anti-automation friction (CAPTCHA), automated account defensive lockouts, and live source IP quarantine.

---

## 🛡️ Core Security Architecture & Module Specifications

| Module | Module Name | Subsystem Role | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Module 1** | **Adaptive User Authentication & Login Management** | **Identity & Access Core** | • User Registration & Form Validation<br>• Dynamic Login Interface & Session State<br>• Cryptographic Password Hashing (**Argon2id & Bcrypt Dual Engine**)<br>• Forensic Login Attempt Monitoring & Audit Trail<br>• User Directory & 1-Click Defensive Account Unlock |
| **Module 2** | **Real-Time Brute-Force Attack Detection & Prevention** | **Threat Defense Engine** | • Real-Time Sliding-Window Attack Detection<br>• Dynamic Anomaly Risk Scoring Algorithm (0–100%)<br>• Server-Side Dynamic Anti-Bot CAPTCHA Challenge Generator<br>• Automated Source IP Tracking & Blacklist Quarantine<br>• Automated Defensive Account Lockouts & Threat Isolation<br>• Live Radar & Real-Time Event Stream (Server-Sent Events) |

---

## 🎨 Design System & Theme Specifications

The platform is designed with an ultra-clean **Light Theme** engineered to match high-end modern cybersecurity products (e.g., Cloudflare, Datadog, CrowdStrike):

- **Primary Background**: `#F8FAFC`
- **Secondary Background / Card Surface**: `#FFFFFF`
- **Primary Blue**: `#2563EB` & **Hover**: `#1D4ED8`
- **Light Blue**: `#DBEAFE` & **Subtle Blue**: `#EFF6FF`
- **Accent Purple**: `#7C3AED` & **Purple Light**: `#EDE9FE`
- **Success Green**: `#16A34A` (`#DCFCE7`)
- **Warning Orange**: `#F59E0B` (`#FEF3C7`)
- **Danger Red**: `#DC2626` (`#FEE2E2`)
- **Main Heading Text**: `#1E293B`
- **Secondary Body Text**: `#64748B`
- **Border Lines**: `#E2E8F0`

Cards feature rounded corners (`12px` to `18px`), subtle multi-layered shadows (`box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.04)`), and dynamic gradients blending `#2563EB` into `#7C3AED`.

---

## 🏗️ Modular Enterprise Backend Architecture

The backend has been modularized into a clean architecture with clear separation of concerns:

```
ethical hacking project/
├── backend/
│   ├── __init__.py               # Application Factory & Blueprint Aggregator
│   ├── config.py                 # Centralized Configuration & Environment Defaults
│   ├── database/
│   │   ├── connection.py         # Dual MySQL (production) & SQLite (embedded) Manager
│   │   ├── schema.py             # Schema Initializer & Index Verifier
│   │   └── seeder.py             # Realistic Forensic Telemetry & Account Seeder
│   ├── security/
│   │   ├── hasher.py             # Module 1: Argon2id & Bcrypt Dual Hasher + Strength Validator
│   │   ├── adaptive_engine.py    # Module 2: Real-Time Sliding-Window Engine & Risk Scorer
│   │   └── captcha_service.py    # Module 2: Dynamic Server-Side Validated Anti-Bot Engine
│   ├── routes/
│   │   ├── auth_routes.py        # /api/auth (Login, Register, Logout, CAPTCHA, Session)
│   │   ├── dashboard_routes.py   # /api/dashboard (Stats, 5 Chart Datasets, Activity Feed, Alerts)
│   │   ├── realtime_routes.py    # /api/realtime (Server-Sent Events Stream, Logs, Simulation)
│   │   ├── analytics_routes.py   # /api/analytics (Trends, Risk Histogram, Target Accounts, Export)
│   │   ├── ip_routes.py          # /api/ip-monitoring (List, Search, Filter, Block, Unblock)
│   │   ├── alerts_routes.py      # /api/alerts (Triage, Severity Filter, Resolve, Dismiss)
│   │   ├── accounts_routes.py    # /api/accounts (Directory, Create, 1-Click Unlock, Reset)
│   │   ├── settings_routes.py    # /api/settings (Get/Update Thresholds, Diagnostics)
│   │   └── history_routes.py     # /api/history (Forensic Audit Trail & CSV Export)
│   └── middleware/
│       └── security_headers.py   # Defense-in-depth HTTP Security Headers (CSP, HSTS, No-Sniff)
├── templates/                    # Jinja2 Templates (12 HTML Views)
├── static/
│   ├── css/style.css             # Light Theme Design System
│   └── js/                       # Real-Time Frontend Controllers
├── schema.sql                    # Production MySQL 8 Schema
├── requirements.txt              # Production Python Dependencies
├── app.py                        # Server Entry Point
├── test_system.py                # System Smoke & Lockout Verification Test Suite
└── test_backend_full.py          # Comprehensive 8-Point API Test Suite
```

---

## 📡 REST API Specifications

### 1. Authentication & Session Management (`/api/auth`)
- `POST /api/auth/register`: Validates user inputs, verifies strong password requirements, hashes with **Argon2id/Bcrypt**, prevents duplicate emails/usernames, and logs registration audit entry.
- `POST /api/auth/login`: Pre-flight adaptive risk evaluation, enforces CAPTCHA challenge if risk &ge; 50% or failed attempts &ge; 3, checks defensive account lockout, timing-attack safe password verification, creates secure session.
- `GET /api/auth/captcha`: Returns fresh dynamic one-time verification challenge (alphanumeric or math).
- `POST /api/auth/captcha/verify`: Server-side token validation test.
- `GET /api/auth/me`: Retrieves current authenticated user context.
- `POST /api/auth/logout`: Terminates active session and records audit event.

### 2. Dashboard Telemetry (`/api/dashboard`)
- `GET /api/dashboard/stats`: Returns real-time KPI metrics (Total Users, Total Logins, Failed Logins, Success Logins, Detected Attacks, Blocked IPs).
- `GET /api/dashboard/charts`: Returns formatted telemetry for all 5 Chart.js charts:
  1. Successful vs Failed Login Attempts (Weekly)
  2. Brute-Force Bursts Over Time (24h Windows)
  3. Diurnal Login Activity by Hour (00:00 to 23:00)
  4. Top Suspicious Source IPs
  5. Security Threat Taxonomy Distribution
- `GET /api/dashboard/activity`: Returns recent 15 authentication requests from database.
- `GET /api/dashboard/alerts`: Returns recent security alerts from intrusion detection system.

### 3. Real-Time Telemetry & Simulation (`/api/realtime`)
- `GET /api/realtime/stream`: **Server-Sent Events (SSE)** high-performance stream. Broadcasts `LOGIN_SUCCESS`, `LOGIN_FAILED`, `CAPTCHA_TRIGGERED`, `ACCOUNT_LOCKED`, `IP_BLOCKED` in real time.
- `GET /api/realtime/logs`: Returns historical terminal packet inspection logs.
- `POST /api/realtime/simulate`: Triggers live simulated brute-force attempts on the backend engine:
  - `single_fail`: Single dictionary probe.
  - `wave`: Multi-IP distributed dictionary wave across proxy IPs.
  - `reset`: Restores baseline telemetry.

### 4. Threat Analytics & Forensics (`/api/analytics`)
- `GET /api/analytics/trends?range=today|7d|30d`: Attack trends vs automated mitigations.
- `GET /api/analytics/risk-distribution`: Histogram distribution across 5 risk brackets.
- `GET /api/analytics/targeted-accounts`: Ranked dictionary target accounts.
- `GET /api/analytics/attacker-ips`: Autonomous system and proxy attack origin vectors.
- `GET /api/analytics/export?format=json|csv`: Generates and downloads forensic reports.

### 5. IP Quarantine & Management (`/api/ip-monitoring`)
- `GET /api/ip-monitoring`: Filter by search term, status (Safe, Suspicious, Blocked), and pagination.
- `POST /api/ip-monitoring/block`: Manually quarantines an IP address with expiration.
- `POST /api/ip-monitoring/unblock`: Restores IP to whitelist status.

### 6. Security Incident Alerts (`/api/alerts`)
- `GET /api/alerts?severity=ALL|CRITICAL|WARNING|INFO`: Filterable incident stream.
- `POST /api/alerts/<id>/resolve`: Marks incident as investigated and resolved.
- `POST /api/alerts/<id>/dismiss`: Removes incident from active feed.

### 7. Identity & Lockout Management (`/api/accounts`)
- `GET /api/accounts`: User directory with status, roles, failed attempt counters, and last login.
- `POST /api/accounts/create`: Creates user with role-based access control.
- `POST /api/accounts/unlock`: **1-Click Defensive Unlock**, clearing brute-force lockouts immediately.
- `POST /api/accounts/lock`: Manual protective account suspension.
- `POST /api/accounts/reset-password`: Regenerates password hash and issues temporary credentials.

### 8. System Parameters & Diagnostics (`/api/settings`)
- `GET /api/settings`: Retrieves live database thresholds.
- `POST /api/settings`: Saves and applies thresholds immediately to the running security engine.
- `POST /api/settings/reset`: Restores baseline default parameters.
- `POST /api/settings/diagnostics`: Runs self-diagnostic checks across all 6 defense subsystems.

### 9. Forensic Audit Trail (`/api/history`)
- `GET /api/history`: Full audit ledger with status filtering, user-agent details, and pagination.
- `GET /api/history/export`: Downloads complete historical audit trail in CSV format.

---

## 🗄️ Database Architecture (8 Core Tables)

1. `users`: Stores user identity credentials, role (Administrator, Security Analyst, Standard User), account status (Active, Locked), failed attempts counter, and Argon2/Bcrypt password hash.
2. `security_settings`: Persists configurable thresholds for failed attempt limit, time window, lockout duration, CAPTCHA limit, and auto IP quarantine.
3. `login_attempts`: Complete historical ledger of every login event (`SUCCESS`, `FAILED`, `CAPTCHA_TRIGGERED`, `ACCOUNT_LOCKED`, `IP_BLOCKED`) with IP, user-agent, risk score, and failure reason.
4. `security_alerts`: Stores high-priority security incidents with alert code, severity level (`CRITICAL`, `WARNING`, `INFO`), and mitigation actions taken.
5. `blocked_ips`: Tracks quarantined IP addresses, probe counts, reason, risk score, and automatic expiration timestamps.
6. `account_lockouts`: Records defensive account suspensions with locked IP, attempt count, lockout expiration, and unlock audit trail.
7. `user_sessions`: Manages active browser sessions, expiry tokens, and revocation state.
8. `audit_logs`: Administrative action ledger tracking privilege changes, user creations, and policy reconfigurations.

---

## 🚀 Running the Project

### 1. Run All Automated Backend Tests
```powershell
python test_system.py
python test_backend_full.py
```
*(All 13 tests pass with 100% verification).*

### 2. Start the Backend Server
```powershell
python app.py
```

### 3. Access in Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Default Demonstration Credentials

| Account Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `Admin@1234` | Full access to command center & parameters |
| **Security Analyst (Mod 1)** | `sec_analyst` | `Analyst@1234` | Security Analyst privileges |
| **Threat Hunter (Mod 2)** | `threat_hunter` | `Hunter@1234` | Attack detection & quarantine privileges |
| **Standard User** | `demo` | `DemoPass123!` | Standard user role |

---

## 🎯 Final-Year Presentation Walkthrough

1. **Adaptive CAPTCHA Challenge**:
   - Go to `http://127.0.0.1:5000/login`.
   - Click the **"Test Attacker Fail"** button 3 times.
   - Observe how the **Risk Level jumps** and the dynamic **CAPTCHA Verification Box automatically appears**.
2. **Defensive Account Lockout**:
   - Continue submitting incorrect passwords until attempt 5 is reached.
   - The account is automatically placed into **Defensive Lockout**, showing a live **10:00 cooldown countdown**.
   - Navigate to **Account Manager** (`/accounts`) as Admin and click **"Unlock"** with 1 click!
3. **Live Attack Radar & Telemetry Stream**:
   - Open `/realtime`.
   - Click **"Start Attack Wave"** in the top simulation controller.
   - Watch real-time radar blips pop on the radar, the forensic terminal stream log packets, and auto-quarantined IP addresses appear in the Quarantined IP list via **Server-Sent Events (SSE)**.
4. **Interactive Security Analytics**:
   - Open `/analytics`.
   - Switch between **Today**, **7 Days**, and **30 Days** filters.
   - Click **"Export Report"** to download the complete forensics JSON report directly from the backend.

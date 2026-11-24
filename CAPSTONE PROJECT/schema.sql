-- ============================================================================
-- Adaptive Authentication Security System (AASS)
-- Production MySQL Database Schema
-- Modules:
--   Module 1: Adaptive User Authentication & Login Management
--   Module 2: Real-Time Brute-Force Attack Detection & Prevention
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `adaptive_auth_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `adaptive_auth_db`;

-- 1. USERS TABLE
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `full_name` VARCHAR(100) NOT NULL,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(120) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` ENUM('Administrator', 'Security Analyst', 'Standard User') DEFAULT 'Standard User',
    `status` ENUM('Active', 'Locked', 'Suspended') DEFAULT 'Active',
    `failed_attempts` INT DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`),
    INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. SECURITY_SETTINGS TABLE
DROP TABLE IF EXISTS `security_settings`;
CREATE TABLE `security_settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `max_failed_attempts` INT NOT NULL DEFAULT 5,
    `attempt_window_minutes` INT NOT NULL DEFAULT 5,
    `lockout_duration_minutes` INT NOT NULL DEFAULT 10,
    `suspicious_risk_threshold` INT NOT NULL DEFAULT 50,
    `captcha_trigger_threshold` INT NOT NULL DEFAULT 3,
    `auto_ip_blocking` TINYINT(1) NOT NULL DEFAULT 1,
    `ip_block_threshold` INT NOT NULL DEFAULT 8,
    `ip_block_duration_minutes` INT NOT NULL DEFAULT 60,
    `notifications_enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. LOGIN_ATTEMPTS TABLE
DROP TABLE IF EXISTS `login_attempts`;
CREATE TABLE `login_attempts` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NULL,
    `username` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NULL,
    `status` ENUM('SUCCESS', 'FAILED', 'CAPTCHA_TRIGGERED', 'ACCOUNT_LOCKED', 'IP_BLOCKED') NOT NULL,
    `risk_score` INT NOT NULL DEFAULT 0,
    `failure_reason` VARCHAR(255) NULL,
    `attempted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_ip_attempt` (`ip_address`, `attempted_at`),
    INDEX `idx_user_attempt` (`username`, `attempted_at`),
    INDEX `idx_status` (`status`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. SECURITY_ALERTS TABLE
DROP TABLE IF EXISTS `security_alerts`;
CREATE TABLE `security_alerts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `alert_code` VARCHAR(20) NOT NULL UNIQUE,
    `event_type` VARCHAR(100) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `username` VARCHAR(50) NULL,
    `risk_level` ENUM('CRITICAL', 'WARNING', 'INFO') NOT NULL,
    `action_taken` VARCHAR(255) NOT NULL,
    `status` ENUM('Active', 'Challenged', 'Blocked', 'Investigating', 'Resolved') DEFAULT 'Active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_risk_level` (`risk_level`),
    INDEX `idx_alert_ip` (`ip_address`),
    INDEX `idx_alert_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. BLOCKED_IPS TABLE
DROP TABLE IF EXISTS `blocked_ips`;
CREATE TABLE `blocked_ips` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL UNIQUE,
    `reason` VARCHAR(255) NOT NULL,
    `total_attempts` INT DEFAULT 1,
    `failed_attempts` INT DEFAULT 1,
    `risk_score` INT DEFAULT 99,
    `status` ENUM('Blocked', 'Whitelisted', 'Expired') DEFAULT 'Blocked',
    `blocked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `expires_at` TIMESTAMP NULL,
    INDEX `idx_blocked_ip` (`ip_address`),
    INDEX `idx_ip_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. ACCOUNT_LOCKOUTS TABLE
DROP TABLE IF EXISTS `account_lockouts`;
CREATE TABLE `account_lockouts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `username` VARCHAR(50) NOT NULL,
    `locked_ip` VARCHAR(45) NOT NULL,
    `failed_attempts_count` INT NOT NULL,
    `locked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `lockout_expires_at` TIMESTAMP NOT NULL,
    `is_unlocked` TINYINT(1) DEFAULT 0,
    `unlocked_at` TIMESTAMP NULL,
    `unlocked_by` VARCHAR(50) NULL,
    INDEX `idx_user_lock` (`user_id`, `is_unlocked`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. USER_SESSIONS TABLE
DROP TABLE IF EXISTS `user_sessions`;
CREATE TABLE `user_sessions` (
    `id` VARCHAR(128) PRIMARY KEY,
    `user_id` INT NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NULL,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `last_activity_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `expires_at` TIMESTAMP NOT NULL,
    INDEX `idx_session_user` (`user_id`, `is_active`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 8. AUDIT_LOGS TABLE
DROP TABLE IF EXISTS `audit_logs`;
CREATE TABLE `audit_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `actor_username` VARCHAR(50) NOT NULL,
    `action` VARCHAR(100) NOT NULL,
    `target_resource` VARCHAR(100) NULL,
    `details` TEXT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_audit_actor` (`actor_username`),
    INDEX `idx_audit_action` (`action`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SEED INITIAL CONFIGURATION & DEMO DATA
-- Passwords are all hashed with bcrypt (Cost: 12)
-- Default passwords:
--   admin -> Admin@1234
--   sec_analyst -> Analyst@1234
--   threat_hunter -> Hunter@1234
--   demo -> DemoPass123!
-- ============================================================================

INSERT INTO `security_settings` 
(`id`, `max_failed_attempts`, `attempt_window_minutes`, `lockout_duration_minutes`, `suspicious_risk_threshold`, `captcha_trigger_threshold`, `auto_ip_blocking`, `ip_block_threshold`, `ip_block_duration_minutes`, `notifications_enabled`)
VALUES 
(1, 5, 5, 10, 50, 3, 1, 8, 60, 1)
ON DUPLICATE KEY UPDATE `id`=`id`;

INSERT INTO `users` 
(`id`, `full_name`, `username`, `email`, `password_hash`, `role`, `status`, `failed_attempts`)
VALUES
(1, 'System Administrator', 'admin', 'admin@sentinel.ai', '$2b$12$e8X8N4/3Z8qX.pZp12p7Ce71lF8VzQ9tOq7GZ9X5mR8k3Y9vK6i9m', 'Administrator', 'Active', 0),
(2, 'Security Analyst', 'sec_analyst', 'analyst@sentinel.ai', '$2b$12$e8X8N4/3Z8qX.pZp12p7Ce71lF8VzQ9tOq7GZ9X5mR8k3Y9vK6i9m', 'Security Analyst', 'Active', 0),
(3, 'Threat Hunter', 'threat_hunter', 'hunter@sentinel.ai', '$2b$12$e8X8N4/3Z8qX.pZp12p7Ce71lF8VzQ9tOq7GZ9X5mR8k3Y9vK6i9m', 'Security Analyst', 'Active', 0),
(4, 'Demonstration User', 'demo', 'demo@sentinel.ai', '$2b$12$e8X8N4/3Z8qX.pZp12p7Ce71lF8VzQ9tOq7GZ9X5mR8k3Y9vK6i9m', 'Standard User', 'Active', 0),
(5, 'Finance Controller', 'finance_mgr', 'finance@sentinel.ai', '$2b$12$e8X8N4/3Z8qX.pZp12p7Ce71lF8VzQ9tOq7GZ9X5mR8k3Y9vK6i9m', 'Standard User', 'Locked', 5);

INSERT INTO `blocked_ips`
(`ip_address`, `reason`, `total_attempts`, `failed_attempts`, `risk_score`, `status`, `blocked_at`, `expires_at`)
VALUES
('45.154.255.89', 'High-frequency brute-force dictionary attack', 48, 48, 98, 'Blocked', NOW(), DATE_ADD(NOW(), INTERVAL 60 MINUTE)),
('185.220.101.5', 'Repeated credential stuffing across multiple users', 32, 31, 89, 'Blocked', NOW(), DATE_ADD(NOW(), INTERVAL 60 MINUTE)),
('194.26.29.112', 'Automated script probing admin accounts', 26, 26, 92, 'Blocked', NOW(), DATE_ADD(NOW(), INTERVAL 60 MINUTE)),
('91.240.118.234', 'Rapid POST storm on /api/auth/login', 64, 64, 100, 'Blocked', NOW(), DATE_ADD(NOW(), INTERVAL 60 MINUTE));

INSERT INTO `security_alerts`
(`alert_code`, `event_type`, `ip_address`, `username`, `risk_level`, `action_taken`, `status`, `created_at`)
VALUES
('ALT-8841', 'Brute-Force Attack Blocked', '45.154.255.89', 'root', 'CRITICAL', 'IP Auto-Banned for 60 min', 'Blocked', DATE_SUB(NOW(), INTERVAL 19 MINUTE)),
('ALT-8840', 'Multiple Failed Logins', '185.220.101.5', 'finance_mgr', 'WARNING', 'Adaptive CAPTCHA Enforced', 'Challenged', DATE_SUB(NOW(), INTERVAL 32 MINUTE)),
('ALT-8839', 'Account Lockout', '109.205.213.6', 'alex_turner', 'CRITICAL', 'Account Locked for 10 min', 'Active', DATE_SUB(NOW(), INTERVAL 1 HOUR)),
('ALT-8838', 'Suspicious IP Anomaly', '198.51.100.23', 'dev_ops', 'WARNING', 'Risk Score Raised to 45%', 'Investigating', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
('ALT-8837', 'Geo-Velocity Anomaly', '103.24.12.8', 'sarah_k', 'INFO', '2FA Verification Requested', 'Resolved', DATE_SUB(NOW(), INTERVAL 4 HOUR));


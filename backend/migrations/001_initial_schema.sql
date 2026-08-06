-- Phase 15: 8 Normalized MySQL Tables Schema

USE capstone_db;

-- 1. users
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('analyst', 'admin') NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. raw_logs
CREATE TABLE IF NOT EXISTS raw_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    event_id INT NOT NULL,
    provider VARCHAR(100),
    hostname VARCHAR(100) NOT NULL,
    username VARCHAR(100),
    source_ip VARCHAR(50),
    process_name VARCHAR(255),
    command_line TEXT,
    scenario_id VARCHAR(100),
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_id (event_id),
    INDEX idx_hostname (hostname),
    INDEX idx_username (username),
    INDEX idx_scenario_id (scenario_id)
) ENGINE=InnoDB;

-- 3. predictions
CREATE TABLE IF NOT EXISTS predictions (
    prediction_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_id BIGINT NOT NULL,
    prediction TINYINT NOT NULL COMMENT '0=Benign, 1=Malicious',
    confidence FLOAT NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id) REFERENCES raw_logs(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. alerts
CREATE TABLE IF NOT EXISTS alerts (
    alert_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    prediction_id BIGINT,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    status ENUM('New', 'Investigating', 'Resolved', 'False Positive') NOT NULL DEFAULT 'New',
    summary TEXT NOT NULL,
    explanation JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (prediction_id) REFERENCES predictions(prediction_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 5. incidents
CREATE TABLE IF NOT EXISTS incidents (
    incident_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_code VARCHAR(50) NOT NULL UNIQUE,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    risk_level ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    status ENUM('Active', 'Closed') NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 6. incident_events
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id BIGINT NOT NULL,
    log_id BIGINT NOT NULL,
    PRIMARY KEY (incident_id, log_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (log_id) REFERENCES raw_logs(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. mitre_mapping
CREATE TABLE IF NOT EXISTS mitre_mapping (
    mapping_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    technique VARCHAR(150) NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    INDEX idx_technique_id (technique_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 8. risk_scores
CREATE TABLE IF NOT EXISTS risk_scores (
    risk_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    score FLOAT NOT NULL,
    level VARCHAR(20) NOT NULL,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
) ENGINE=InnoDB;

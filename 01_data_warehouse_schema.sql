-- ============================================================
-- CYBERSECURITY LOG MONITORING SYSTEM
-- Data Warehouse - Star Schema Design
-- ============================================================

-- ========================
-- DIMENSION TABLES
-- ========================

-- DIM: Time Dimension
CREATE TABLE dim_time (
    time_key        INT PRIMARY KEY,
    full_datetime   TIMESTAMP NOT NULL,
    date_day        DATE,
    hour            TINYINT,
    minute          TINYINT,
    day_of_week     VARCHAR(10),
    week_of_year    TINYINT,
    month           TINYINT,
    month_name      VARCHAR(10),
    quarter         TINYINT,
    year            SMALLINT,
    is_weekend      BOOLEAN,
    is_holiday      BOOLEAN
);

-- DIM: Source IP / User
CREATE TABLE dim_user (
    user_key        INT PRIMARY KEY AUTOINCREMENT,
    user_id         VARCHAR(50) UNIQUE,
    username        VARCHAR(100),
    department      VARCHAR(100),
    role            VARCHAR(50),
    country         VARCHAR(60),
    city            VARCHAR(60),
    is_privileged   BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DIM: Host/Device
CREATE TABLE dim_host (
    host_key        INT PRIMARY KEY AUTOINCREMENT,
    host_id         VARCHAR(50) UNIQUE,
    hostname        VARCHAR(150),
    ip_address      VARCHAR(45),   -- supports IPv6
    os_type         VARCHAR(50),
    os_version      VARCHAR(50),
    environment     VARCHAR(20),   -- PROD, DEV, STAGING
    datacenter      VARCHAR(50),
    criticality     VARCHAR(10)    -- LOW, MEDIUM, HIGH, CRITICAL
);

-- DIM: Attack Type / Threat Category
CREATE TABLE dim_threat (
    threat_key      INT PRIMARY KEY AUTOINCREMENT,
    threat_type     VARCHAR(50),   -- e.g. Brute Force, SQL Injection
    threat_category VARCHAR(50),   -- e.g. Authentication, Intrusion
    mitre_tactic    VARCHAR(100),  -- MITRE ATT&CK mapping
    mitre_technique VARCHAR(100),
    severity        VARCHAR(10),   -- LOW, MEDIUM, HIGH, CRITICAL
    cve_id          VARCHAR(30),
    description     TEXT
);

-- DIM: Log Source
CREATE TABLE dim_log_source (
    source_key      INT PRIMARY KEY AUTOINCREMENT,
    source_name     VARCHAR(100),
    source_type     VARCHAR(50),   -- Firewall, IDS, SIEM, App, OS
    vendor          VARCHAR(100),
    log_format      VARCHAR(30),   -- JSON, CEF, SYSLOG, XML
    is_active       BOOLEAN DEFAULT TRUE
);

-- ========================
-- FACT TABLE
-- ========================

CREATE TABLE fact_security_events (
    event_key           BIGINT PRIMARY KEY AUTOINCREMENT,
    time_key            INT REFERENCES dim_time(time_key),
    user_key            INT REFERENCES dim_user(user_key),
    host_key            INT REFERENCES dim_host(host_key),
    threat_key          INT REFERENCES dim_threat(threat_key),
    source_key          INT REFERENCES dim_log_source(source_key),

    -- Degenerate Dimensions
    raw_event_id        VARCHAR(100),
    session_id          VARCHAR(100),

    -- Measures
    event_count         INT DEFAULT 1,
    bytes_transferred   BIGINT,
    duration_seconds    FLOAT,
    failed_attempts     INT DEFAULT 0,
    alert_score         FLOAT,       -- ML anomaly score 0-100

    -- Status & Outcome
    event_status        VARCHAR(20), -- BLOCKED, ALLOWED, ALERTED
    response_action     VARCHAR(50), -- NONE, QUARANTINE, BLOCK, NOTIFY
    is_false_positive   BOOLEAN DEFAULT FALSE,
    is_investigated     BOOLEAN DEFAULT FALSE,

    -- Semi-structured metadata (Snowflake VARIANT)
    raw_log_json        VARIANT,

    -- Audit
    ingested_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP
)
CLUSTER BY (time_key, threat_key)   -- Snowflake Clustering Key
PARTITION BY (TO_DATE(ingested_at)); -- Partition for performance

-- ========================
-- AGGREGATE / SUMMARY TABLES
-- ========================

CREATE TABLE agg_hourly_threats (
    agg_key         INT PRIMARY KEY AUTOINCREMENT,
    hour_bucket     TIMESTAMP,
    threat_type     VARCHAR(50),
    environment     VARCHAR(20),
    total_events    INT,
    blocked_events  INT,
    high_severity   INT,
    unique_sources  INT,
    avg_alert_score FLOAT,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agg_user_risk_score (
    user_key            INT REFERENCES dim_user(user_key),
    score_date          DATE,
    risk_score          FLOAT,     -- 0-100
    total_events        INT,
    failed_logins       INT,
    anomalous_behavior  INT,
    privileged_actions  INT,
    PRIMARY KEY (user_key, score_date)
);

-- ========================
-- INDEXES FOR PERFORMANCE
-- ========================

CREATE INDEX idx_fact_time     ON fact_security_events(time_key);
CREATE INDEX idx_fact_user     ON fact_security_events(user_key);
CREATE INDEX idx_fact_host     ON fact_security_events(host_key);
CREATE INDEX idx_fact_threat   ON fact_security_events(threat_key);
CREATE INDEX idx_fact_status   ON fact_security_events(event_status);
CREATE INDEX idx_fact_ingested ON fact_security_events(ingested_at);
CREATE INDEX idx_host_ip       ON dim_host(ip_address);
CREATE INDEX idx_user_id       ON dim_user(user_id);

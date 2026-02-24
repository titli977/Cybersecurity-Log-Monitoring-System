-- ============================================================
-- CYBERSECURITY LOG MONITORING SYSTEM
-- Snowflake: Clustering, Time Travel, RBAC, Data Masking,
--            Semi-Structured Data, Governance
-- ============================================================

-- ========================
-- DATABASE SETUP
-- ========================

CREATE DATABASE IF NOT EXISTS CYBERSEC_DB;
CREATE SCHEMA  IF NOT EXISTS CYBERSEC_DB.RAW;
CREATE SCHEMA  IF NOT EXISTS CYBERSEC_DB.STAGING;
CREATE SCHEMA  IF NOT EXISTS CYBERSEC_DB.ANALYTICS;
CREATE SCHEMA  IF NOT EXISTS CYBERSEC_DB.GOVERNANCE;

USE DATABASE CYBERSEC_DB;
USE SCHEMA ANALYTICS;

-- ========================
-- WAREHOUSES (sizing by use-case)
-- ========================

CREATE WAREHOUSE IF NOT EXISTS ETL_WH
    WAREHOUSE_SIZE = 'MEDIUM'
    AUTO_SUSPEND   = 60
    AUTO_RESUME    = TRUE
    COMMENT        = 'ETL/ELT pipeline warehouse';

CREATE WAREHOUSE IF NOT EXISTS ANALYTICS_WH
    WAREHOUSE_SIZE = 'SMALL'
    AUTO_SUSPEND   = 120
    AUTO_RESUME    = TRUE
    COMMENT        = 'Analyst queries';

CREATE WAREHOUSE IF NOT EXISTS STREAMING_WH
    WAREHOUSE_SIZE = 'LARGE'
    AUTO_SUSPEND   = 30
    AUTO_RESUME    = TRUE
    COMMENT        = 'Real-time streaming ingest';


-- ========================
-- MAIN FACT TABLE WITH CLUSTERING
-- ========================

CREATE TABLE IF NOT EXISTS fact_security_events (
    event_key           NUMBER AUTOINCREMENT PRIMARY KEY,
    time_key            NUMBER,
    user_key            NUMBER,
    host_key            NUMBER,
    threat_key          NUMBER,
    source_key          NUMBER,

    raw_event_id        VARCHAR(100),
    session_id          VARCHAR(100),

    event_count         NUMBER DEFAULT 1,
    bytes_transferred   NUMBER,
    duration_seconds    FLOAT,
    failed_attempts     NUMBER DEFAULT 0,
    alert_score         FLOAT,

    event_status        VARCHAR(20),
    response_action     VARCHAR(50),
    is_false_positive   BOOLEAN DEFAULT FALSE,
    is_investigated     BOOLEAN DEFAULT FALSE,

    -- Semi-structured column (JSON/VARIANT)
    raw_log_json        VARIANT,

    ingested_at         TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at          TIMESTAMP_NTZ
)
-- Clustering key: optimizes range scans on time + threat
CLUSTER BY (TO_DATE(ingested_at), threat_key, event_status)
DATA_RETENTION_TIME_IN_DAYS = 90   -- Time Travel: 90 days
COMMENT = 'Fact table for all security events';


-- ========================
-- SEMI-STRUCTURED DATA QUERIES
-- ========================

-- Query nested JSON inside VARIANT column
SELECT
    raw_event_id,
    raw_log_json:original:source_ip::STRING        AS source_ip,
    raw_log_json:original:description::STRING      AS description,
    raw_log_json:payload:log_source::STRING        AS log_source,
    raw_log_json:payload:os_type::STRING           AS os_type,
    raw_log_json:payload:env::STRING               AS environment,
    PARSE_JSON(raw_log_json):payload:session_id    AS session_id
FROM fact_security_events
WHERE raw_log_json:original:source_ip IS NOT NULL
LIMIT 100;

-- FLATTEN array in VARIANT (e.g. list of CVEs)
SELECT
    event_key,
    f.value::STRING AS cve_id
FROM fact_security_events,
LATERAL FLATTEN(input => raw_log_json:cve_ids) f
WHERE raw_log_json:cve_ids IS NOT NULL;


-- ========================
-- TIME TRAVEL EXAMPLES
-- ========================

-- Query data as it was 24 hours ago
SELECT COUNT(*) AS events_24h_ago
FROM fact_security_events
AT (OFFSET => -86400);

-- Query at specific timestamp (before a bad data load)
SELECT *
FROM fact_security_events
AT (TIMESTAMP => '2024-06-01 10:00:00'::TIMESTAMP);

-- Restore accidentally deleted rows using Time Travel
CREATE TABLE fact_security_events_backup
AS SELECT * FROM fact_security_events
   BEFORE (STATEMENT => '<query_id_of_delete>');

-- Undrop a table
-- DROP TABLE fact_security_events;   -- oops
UNDROP TABLE fact_security_events;


-- ========================
-- RBAC (Role-Based Access Control)
-- ========================

-- Create roles
CREATE ROLE IF NOT EXISTS CYBERSEC_ADMIN;
CREATE ROLE IF NOT EXISTS CYBERSEC_ANALYST;
CREATE ROLE IF NOT EXISTS CYBERSEC_READONLY;
CREATE ROLE IF NOT EXISTS CYBERSEC_ETL_ROLE;

-- Grant hierarchy
GRANT ROLE CYBERSEC_ANALYST  TO ROLE CYBERSEC_ADMIN;
GRANT ROLE CYBERSEC_READONLY TO ROLE CYBERSEC_ANALYST;

-- Admin: full access
GRANT ALL PRIVILEGES ON DATABASE CYBERSEC_DB       TO ROLE CYBERSEC_ADMIN;
GRANT ALL PRIVILEGES ON ALL SCHEMAS IN DATABASE CYBERSEC_DB TO ROLE CYBERSEC_ADMIN;
GRANT ALL PRIVILEGES ON ALL TABLES  IN SCHEMA CYBERSEC_DB.ANALYTICS TO ROLE CYBERSEC_ADMIN;

-- Analyst: read + view access, masked data
GRANT USAGE ON DATABASE CYBERSEC_DB                    TO ROLE CYBERSEC_ANALYST;
GRANT USAGE ON SCHEMA  CYBERSEC_DB.ANALYTICS           TO ROLE CYBERSEC_ANALYST;
GRANT SELECT ON VIEW vw_analyst_events                  TO ROLE CYBERSEC_ANALYST;
GRANT SELECT ON ALL TABLES IN SCHEMA CYBERSEC_DB.ANALYTICS TO ROLE CYBERSEC_ANALYST;

-- Read-only: view only
GRANT USAGE  ON DATABASE CYBERSEC_DB             TO ROLE CYBERSEC_READONLY;
GRANT USAGE  ON SCHEMA   CYBERSEC_DB.ANALYTICS   TO ROLE CYBERSEC_READONLY;
GRANT SELECT ON VIEW vw_analyst_events           TO ROLE CYBERSEC_READONLY;

-- ETL: insert/update staging only
GRANT USAGE  ON SCHEMA   CYBERSEC_DB.RAW           TO ROLE CYBERSEC_ETL_ROLE;
GRANT INSERT ON ALL TABLES IN SCHEMA CYBERSEC_DB.RAW TO ROLE CYBERSEC_ETL_ROLE;
GRANT USAGE  ON WAREHOUSE ETL_WH                   TO ROLE CYBERSEC_ETL_ROLE;

-- Assign roles to users
-- GRANT ROLE CYBERSEC_ADMIN   TO USER john_admin;
-- GRANT ROLE CYBERSEC_ANALYST TO USER jane_analyst;
-- GRANT ROLE CYBERSEC_READONLY TO USER bob_manager;


-- ========================
-- DATA MASKING POLICIES
-- ========================

USE SCHEMA CYBERSEC_DB.GOVERNANCE;

-- Mask IP address (last octet)
CREATE OR REPLACE MASKING POLICY mask_ip_address AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('CYBERSEC_ADMIN') THEN val
        ELSE REGEXP_REPLACE(val, '\\d+$', 'xxx')
    END;

-- Mask username
CREATE OR REPLACE MASKING POLICY mask_username AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('CYBERSEC_ADMIN') THEN val
        ELSE LEFT(val, 3) || '***'
    END;

-- Mask alert score (analysts see rounded, admins see exact)
CREATE OR REPLACE MASKING POLICY mask_alert_score AS (val FLOAT) RETURNS FLOAT ->
    CASE
        WHEN CURRENT_ROLE() IN ('CYBERSEC_ADMIN') THEN val
        ELSE ROUND(val, -1)   -- round to nearest 10
    END;

-- Apply masking policies to columns
ALTER TABLE CYBERSEC_DB.ANALYTICS.dim_host
    MODIFY COLUMN ip_address SET MASKING POLICY CYBERSEC_DB.GOVERNANCE.mask_ip_address;

ALTER TABLE CYBERSEC_DB.ANALYTICS.dim_user
    MODIFY COLUMN username SET MASKING POLICY CYBERSEC_DB.GOVERNANCE.mask_username;

ALTER TABLE CYBERSEC_DB.ANALYTICS.fact_security_events
    MODIFY COLUMN alert_score SET MASKING POLICY CYBERSEC_DB.GOVERNANCE.mask_alert_score;


-- ========================
-- ROW ACCESS POLICY (additional governance)
-- ========================

CREATE OR REPLACE ROW ACCESS POLICY restrict_prod_data AS (environment VARCHAR) RETURNS BOOLEAN ->
    CASE
        WHEN CURRENT_ROLE() IN ('CYBERSEC_ADMIN') THEN TRUE
        WHEN environment = 'PROD' AND CURRENT_ROLE() = 'CYBERSEC_ANALYST' THEN TRUE
        WHEN environment = 'DEV'  THEN TRUE
        ELSE FALSE
    END;

-- Apply to host dimension
ALTER TABLE CYBERSEC_DB.ANALYTICS.dim_host
    ADD ROW ACCESS POLICY CYBERSEC_DB.GOVERNANCE.restrict_prod_data ON (environment);


-- ========================
-- PERFORMANCE TUNING
-- ========================

-- Automatic Clustering Maintenance
ALTER TABLE CYBERSEC_DB.ANALYTICS.fact_security_events
    RESUME RECLUSTER;

-- Materialized View for heavy aggregations
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_threat_summary AS
SELECT
    TO_DATE(ingested_at)  AS event_date,
    dt.threat_type,
    dt.severity,
    dh.environment,
    COUNT(*)              AS total_events,
    SUM(failed_attempts)  AS total_failures,
    AVG(alert_score)      AS avg_score,
    MAX(alert_score)      AS max_score,
    SUM(bytes_transferred) AS total_bytes
FROM fact_security_events fse
JOIN dim_threat dt ON fse.threat_key = dt.threat_key
JOIN dim_host   dh ON fse.host_key   = dh.host_key
GROUP BY 1, 2, 3, 4;

-- Search Optimization for point lookups
ALTER TABLE CYBERSEC_DB.ANALYTICS.fact_security_events
    ADD SEARCH OPTIMIZATION ON EQUALITY(raw_event_id, session_id);

-- Query acceleration
ALTER WAREHOUSE ANALYTICS_WH SET
    MAX_CLUSTER_COUNT = 3
    MIN_CLUSTER_COUNT = 1
    SCALING_POLICY    = 'ECONOMY';

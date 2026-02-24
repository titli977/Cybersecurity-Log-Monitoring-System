-- ============================================================
-- CYBERSECURITY LOG MONITORING SYSTEM
-- Advanced SQL: CTEs, Window Functions, Partitioning, Indexing
-- ============================================================

-- ========================
-- 1. CTE: Top Threat Summary with Recursive Drill-Down
-- ========================

WITH threat_summary AS (
    SELECT
        dt.threat_type,
        dt.threat_category,
        dt.severity,
        dt.mitre_tactic,
        COUNT(*)                          AS total_events,
        SUM(fse.event_count)              AS total_count,
        AVG(fse.alert_score)              AS avg_score,
        SUM(CASE WHEN fse.event_status = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked_count
    FROM fact_security_events fse
    JOIN dim_threat dt ON fse.threat_key = dt.threat_key
    JOIN dim_time   ti ON fse.time_key   = ti.time_key
    WHERE ti.full_datetime >= DATEADD('day', -30, CURRENT_TIMESTAMP)
    GROUP BY dt.threat_type, dt.threat_category, dt.severity, dt.mitre_tactic
),
ranked_threats AS (
    SELECT *,
        ROUND(100.0 * blocked_count / NULLIF(total_events,0), 2) AS block_rate_pct,
        RANK() OVER (PARTITION BY threat_category ORDER BY total_events DESC) AS rank_in_category
    FROM threat_summary
)
SELECT *
FROM ranked_threats
WHERE rank_in_category <= 5
ORDER BY total_events DESC;


-- ========================
-- 2. Window Functions: User Behavior Anomaly Detection
-- ========================

WITH user_daily_activity AS (
    SELECT
        du.username,
        du.department,
        ti.date_day,
        COUNT(*)                    AS daily_events,
        SUM(fse.failed_attempts)    AS daily_failures,
        AVG(fse.alert_score)        AS avg_alert_score
    FROM fact_security_events fse
    JOIN dim_user du ON fse.user_key = du.user_key
    JOIN dim_time ti ON fse.time_key = ti.time_key
    GROUP BY du.username, du.department, ti.date_day
),
user_stats AS (
    SELECT *,
        AVG(daily_events)   OVER (PARTITION BY username ORDER BY date_day
                                   ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS rolling_7d_avg,
        STDDEV(daily_events) OVER (PARTITION BY username ORDER BY date_day
                                   ROWS BETWEEN 29 PRECEDING AND CURRENT ROW) AS rolling_30d_std,
        LAG(daily_events, 1)  OVER (PARTITION BY username ORDER BY date_day) AS prev_day_events,
        SUM(daily_failures)   OVER (PARTITION BY username ORDER BY date_day
                                   ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS rolling_7d_failures,
        PERCENT_RANK()        OVER (PARTITION BY department ORDER BY daily_events DESC) AS dept_percentile,
        NTILE(4)              OVER (ORDER BY daily_events DESC) AS activity_quartile
    FROM user_daily_activity
)
SELECT
    username, department, date_day,
    daily_events, rolling_7d_avg, rolling_30d_std,
    dept_percentile,
    CASE
        WHEN daily_events > (rolling_7d_avg + 2 * rolling_30d_std)
        THEN 'ANOMALY - SPIKE'
        WHEN rolling_7d_failures > 20
        THEN 'ANOMALY - REPEATED FAILURES'
        ELSE 'NORMAL'
    END AS anomaly_flag
FROM user_stats
WHERE date_day = CURRENT_DATE - 1
ORDER BY daily_events DESC;


-- ========================
-- 3. CTE: Lateral Movement Detection (Same user, multiple hosts)
-- ========================

WITH user_host_sessions AS (
    SELECT
        du.user_id,
        du.username,
        fse.session_id,
        dh.hostname,
        dh.environment,
        ti.full_datetime,
        LEAD(dh.hostname) OVER (
            PARTITION BY du.user_id, fse.session_id
            ORDER BY ti.full_datetime
        ) AS next_host,
        LEAD(ti.full_datetime) OVER (
            PARTITION BY du.user_id, fse.session_id
            ORDER BY ti.full_datetime
        ) AS next_time
    FROM fact_security_events fse
    JOIN dim_user du ON fse.user_key = du.user_key
    JOIN dim_host dh ON fse.host_key = dh.host_key
    JOIN dim_time ti ON fse.time_key = ti.time_key
    WHERE ti.full_datetime >= DATEADD('hour', -24, CURRENT_TIMESTAMP)
),
lateral_movement AS (
    SELECT
        user_id, username, session_id,
        hostname AS from_host,
        next_host AS to_host,
        full_datetime AS hop_time,
        DATEDIFF('minute', full_datetime, next_time) AS minutes_between_hops,
        COUNT(*) OVER (PARTITION BY user_id, session_id) AS total_hops
    FROM user_host_sessions
    WHERE next_host IS NOT NULL AND hostname <> next_host
)
SELECT *,
    CASE WHEN total_hops >= 3 AND minutes_between_hops < 10
         THEN 'HIGH RISK - RAPID LATERAL MOVEMENT'
         WHEN total_hops >= 2
         THEN 'MEDIUM RISK - LATERAL MOVEMENT'
         ELSE 'MONITOR'
    END AS risk_flag
FROM lateral_movement
ORDER BY total_hops DESC, hop_time;


-- ========================
-- 4. Partitioned Query: Time-based analysis with partition pruning
-- ========================

-- Snowflake uses micro-partitions; this query benefits from partition pruning
SELECT
    TO_DATE(ingested_at)  AS event_date,
    dt.severity,
    dh.environment,
    COUNT(*)              AS event_count,
    AVG(alert_score)      AS avg_score,
    MAX(alert_score)      AS max_score,
    SUM(bytes_transferred) AS total_bytes
FROM fact_security_events fse
JOIN dim_threat dt ON fse.threat_key = dt.threat_key
JOIN dim_host   dh ON fse.host_key   = dh.host_key
WHERE ingested_at BETWEEN '2024-01-01' AND '2024-12-31'  -- partition pruning
  AND dt.severity IN ('HIGH', 'CRITICAL')
GROUP BY GROUPING SETS (
    (event_date, severity, environment),
    (event_date, severity),
    (severity)
)
ORDER BY event_date DESC, event_count DESC;


-- ========================
-- 5. Real-Time Alert: Brute Force Detection (sliding window)
-- ========================

WITH login_attempts AS (
    SELECT
        du.user_id,
        du.username,
        dh.ip_address,
        ti.full_datetime,
        fse.failed_attempts,
        SUM(fse.failed_attempts) OVER (
            PARTITION BY du.user_id
            ORDER BY ti.full_datetime
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
        ) AS failures_last_5min
    FROM fact_security_events fse
    JOIN dim_user du ON fse.user_key = du.user_key
    JOIN dim_host dh ON fse.host_key = dh.host_key
    JOIN dim_time ti ON fse.time_key = ti.time_key
    JOIN dim_threat dt ON fse.threat_key = dt.threat_key
    WHERE dt.threat_type = 'Authentication Failure'
      AND ti.full_datetime >= DATEADD('minute', -30, CURRENT_TIMESTAMP)
)
SELECT DISTINCT
    user_id, username, ip_address,
    failures_last_5min,
    CASE
        WHEN failures_last_5min >= 50 THEN 'BLOCK IMMEDIATELY'
        WHEN failures_last_5min >= 20 THEN 'HIGH ALERT'
        WHEN failures_last_5min >= 10 THEN 'MONITOR'
        ELSE 'NORMAL'
    END AS recommended_action
FROM login_attempts
WHERE failures_last_5min >= 10
ORDER BY failures_last_5min DESC;


-- ========================
-- 6. RBAC Views (Security)
-- ========================

-- Analyst view: masked sensitive fields
CREATE OR REPLACE SECURE VIEW vw_analyst_events AS
SELECT
    fse.event_key,
    ti.full_datetime,
    dt.threat_type,
    dt.severity,
    dh.environment,
    -- Mask last octet of IP
    REGEXP_REPLACE(dh.ip_address, '\\d+$', 'xxx') AS masked_ip,
    -- Mask username to first 3 chars
    LEFT(du.username, 3) || '***'                  AS masked_username,
    fse.event_status,
    fse.alert_score
FROM fact_security_events fse
JOIN dim_time   ti ON fse.time_key   = ti.time_key
JOIN dim_threat dt ON fse.threat_key = dt.threat_key
JOIN dim_host   dh ON fse.host_key   = dh.host_key
JOIN dim_user   du ON fse.user_key   = du.user_key;

-- Admin view: full access
CREATE OR REPLACE SECURE VIEW vw_admin_events AS
SELECT fse.*, ti.*, dt.*, dh.*, du.*
FROM fact_security_events fse
JOIN dim_time   ti ON fse.time_key   = ti.time_key
JOIN dim_threat dt ON fse.threat_key = dt.threat_key
JOIN dim_host   dh ON fse.host_key   = dh.host_key
JOIN dim_user   du ON fse.user_key   = du.user_key;

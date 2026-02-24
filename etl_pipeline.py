"""
============================================================
CYBERSECURITY LOG MONITORING SYSTEM
Python ETL/ELT Pipeline
============================================================
Ingests raw security logs → validates → transforms → loads
into Snowflake Data Warehouse
"""

import os
import json
import hashlib
import logging
import random
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
import re

# ── Optional imports (graceful fallback for demo) ────────
try:
    import pandas as pd
    import numpy as np
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import snowflake.connector
    HAS_SNOWFLAKE = True
except ImportError:
    HAS_SNOWFLAKE = False

# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("etl_pipeline.log", mode="a"),
    ],
)
logger = logging.getLogger("cybersec_etl")


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
EVENT_STATUSES   = ["BLOCKED", "ALLOWED", "ALERTED"]
THREAT_TYPES     = [
    "Brute Force", "SQL Injection", "XSS", "Port Scan",
    "DDoS", "Phishing", "Malware", "Privilege Escalation",
    "Data Exfiltration", "Authentication Failure",
]
OS_TYPES   = ["Windows Server", "Ubuntu", "CentOS", "Debian", "Windows 10"]
ENVS       = ["PROD", "DEV", "STAGING"]
DEPTS      = ["Engineering", "Finance", "HR", "Legal", "Operations"]
LOG_SOURCES = ["Firewall", "IDS/IPS", "WAF", "SIEM", "EDR", "OS Audit"]


@dataclass
class RawLogEvent:
    event_id:         str
    timestamp:        str
    source_ip:        str
    destination_ip:   str
    username:         str
    hostname:         str
    event_type:       str
    severity:         str
    description:      str
    bytes_transferred: int
    failed_attempts:  int
    alert_score:      float
    raw_payload:      dict = field(default_factory=dict)


@dataclass
class TransformedEvent:
    event_id:          str
    event_datetime:    datetime
    user_id:           str
    username:          str
    department:        str
    host_id:           str
    hostname:          str
    ip_address:        str
    environment:       str
    os_type:           str
    threat_type:       str
    threat_category:   str
    severity:          str
    mitre_tactic:      str
    log_source_type:   str
    event_status:      str
    bytes_transferred: int
    failed_attempts:   int
    alert_score:       float
    raw_log_json:      str    # JSON string for VARIANT column
    ingested_at:       datetime = field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# Step 1: Extractor
# ─────────────────────────────────────────────

class LogExtractor:
    """Simulate extracting logs from multiple sources."""

    MITRE_MAP = {
        "Brute Force":            ("Credential Access",    "T1110"),
        "SQL Injection":          ("Initial Access",       "T1190"),
        "XSS":                    ("Execution",            "T1059"),
        "Port Scan":              ("Discovery",            "T1046"),
        "DDoS":                   ("Impact",               "T1498"),
        "Phishing":               ("Initial Access",       "T1566"),
        "Malware":                ("Execution",            "T1204"),
        "Privilege Escalation":   ("Privilege Escalation", "T1068"),
        "Data Exfiltration":      ("Exfiltration",         "T1041"),
        "Authentication Failure": ("Credential Access",    "T1078"),
    }

    THREAT_CATEGORIES = {
        "Brute Force": "Authentication",
        "SQL Injection": "Injection",
        "XSS": "Injection",
        "Port Scan": "Reconnaissance",
        "DDoS": "Availability",
        "Phishing": "Social Engineering",
        "Malware": "Malware",
        "Privilege Escalation": "Privilege Abuse",
        "Data Exfiltration": "Data Theft",
        "Authentication Failure": "Authentication",
    }

    def _random_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _random_event_id(self) -> str:
        return hashlib.md5(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:16].upper()

    def extract_batch(self, n: int = 100) -> list[RawLogEvent]:
        logger.info(f"Extracting batch of {n} log events …")
        events = []
        base_time = datetime.utcnow() - timedelta(hours=random.randint(0, 23))

        for i in range(n):
            event_type = random.choice(THREAT_TYPES)
            events.append(RawLogEvent(
                event_id         = self._random_event_id(),
                timestamp        = (base_time - timedelta(seconds=random.randint(0, 86400))).isoformat(),
                source_ip        = self._random_ip(),
                destination_ip   = self._random_ip(),
                username         = f"user_{random.randint(1000, 9999)}",
                hostname         = f"host-{random.choice(['web','db','app','mail'])}-{random.randint(1,20):02d}",
                event_type       = event_type,
                severity         = random.choices(
                                       SEVERITY_LEVELS,
                                       weights=[40, 30, 20, 10]
                                   )[0],
                description      = f"{event_type} detected from {self._random_ip()}",
                bytes_transferred= random.randint(0, 5_000_000),
                failed_attempts  = random.randint(0, 100),
                alert_score      = round(random.uniform(0, 100), 2),
                raw_payload      = {
                    "log_source": random.choice(LOG_SOURCES),
                    "os_type":    random.choice(OS_TYPES),
                    "env":        random.choice(ENVS),
                    "dept":       random.choice(DEPTS),
                    "session_id": hashlib.md5(str(i).encode()).hexdigest()[:8],
                },
            ))

        logger.info(f"Extracted {len(events)} events successfully.")
        return events


# ─────────────────────────────────────────────
# Step 2: Transformer
# ─────────────────────────────────────────────

class LogTransformer:

    MITRE_MAP = LogExtractor.MITRE_MAP
    THREAT_CATEGORIES = LogExtractor.THREAT_CATEGORIES

    def _validate(self, event: RawLogEvent) -> list[str]:
        errors = []
        if not event.event_id:
            errors.append("Missing event_id")
        try:
            datetime.fromisoformat(event.timestamp)
        except (ValueError, TypeError):
            errors.append(f"Invalid timestamp: {event.timestamp}")
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not ip_pattern.match(event.source_ip):
            errors.append(f"Invalid IP: {event.source_ip}")
        if event.severity not in SEVERITY_LEVELS:
            errors.append(f"Unknown severity: {event.severity}")
        if event.alert_score < 0 or event.alert_score > 100:
            errors.append(f"Alert score out of range: {event.alert_score}")
        return errors

    def _determine_status(self, event: RawLogEvent) -> str:
        if event.alert_score >= 80 or event.severity == "CRITICAL":
            return "BLOCKED"
        if event.alert_score >= 50 or event.severity == "HIGH":
            return "ALERTED"
        return "ALLOWED"

    def transform(self, events: list[RawLogEvent]) -> tuple[list[TransformedEvent], list[dict]]:
        transformed, rejected = [], []
        mitre_map  = self.MITRE_MAP
        cat_map    = self.THREAT_CATEGORIES

        for ev in events:
            errors = self._validate(ev)
            if errors:
                rejected.append({"event_id": ev.event_id, "errors": errors})
                continue

            tactic, technique = mitre_map.get(ev.event_type, ("Unknown", "T0000"))
            category          = cat_map.get(ev.event_type, "Other")
            status            = self._determine_status(ev)

            transformed.append(TransformedEvent(
                event_id          = ev.event_id,
                event_datetime    = datetime.fromisoformat(ev.timestamp),
                user_id           = f"USR-{ev.username.upper()}",
                username          = ev.username,
                department        = ev.raw_payload.get("dept", "Unknown"),
                host_id           = f"HST-{ev.hostname.upper()}",
                hostname          = ev.hostname,
                ip_address        = ev.source_ip,
                environment       = ev.raw_payload.get("env", "PROD"),
                os_type           = ev.raw_payload.get("os_type", "Unknown"),
                threat_type       = ev.event_type,
                threat_category   = category,
                severity          = ev.severity,
                mitre_tactic      = tactic,
                log_source_type   = ev.raw_payload.get("log_source", "Unknown"),
                event_status      = status,
                bytes_transferred = ev.bytes_transferred,
                failed_attempts   = ev.failed_attempts,
                alert_score       = ev.alert_score,
                raw_log_json      = json.dumps({
                    "original": {
                        "event_id":    ev.event_id,
                        "source_ip":   ev.source_ip,
                        "dest_ip":     ev.destination_ip,
                        "description": ev.description,
                    },
                    "payload":  ev.raw_payload,
                }),
            ))

        logger.info(
            f"Transform complete — accepted: {len(transformed)}, "
            f"rejected: {len(rejected)}"
        )
        return transformed, rejected


# ─────────────────────────────────────────────
# Step 3: Loader (Snowflake)
# ─────────────────────────────────────────────

class SnowflakeLoader:
    """Loads transformed events into Snowflake staging table."""

    STAGING_DDL = """
    CREATE TABLE IF NOT EXISTS stg_security_events (
        event_id          VARCHAR(50),
        event_datetime    TIMESTAMP,
        user_id           VARCHAR(50),
        username          VARCHAR(100),
        department        VARCHAR(100),
        host_id           VARCHAR(50),
        hostname          VARCHAR(150),
        ip_address        VARCHAR(45),
        environment       VARCHAR(20),
        os_type           VARCHAR(50),
        threat_type       VARCHAR(50),
        threat_category   VARCHAR(50),
        severity          VARCHAR(10),
        mitre_tactic      VARCHAR(100),
        log_source_type   VARCHAR(50),
        event_status      VARCHAR(20),
        bytes_transferred BIGINT,
        failed_attempts   INT,
        alert_score       FLOAT,
        raw_log_json      VARIANT,
        ingested_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """

    def __init__(self, config: dict):
        self.config = config
        self.conn   = None

    def connect(self):
        if not HAS_SNOWFLAKE:
            logger.warning("snowflake-connector-python not installed — running in DRY-RUN mode.")
            return
        logger.info("Connecting to Snowflake …")
        self.conn = snowflake.connector.connect(**self.config)
        logger.info("Connected to Snowflake.")

    def load(self, events: list[TransformedEvent], dry_run: bool = False):
        if dry_run or not self.conn:
            logger.info(f"[DRY-RUN] Would load {len(events)} events to Snowflake staging.")
            for ev in events[:3]:
                logger.info(f"  Sample: {ev.event_id} | {ev.threat_type} | {ev.severity} | {ev.event_status}")
            return

        cursor = self.conn.cursor()
        cursor.execute(self.STAGING_DDL)

        insert_sql = """
        INSERT INTO stg_security_events
            (event_id, event_datetime, user_id, username, department,
             host_id, hostname, ip_address, environment, os_type,
             threat_type, threat_category, severity, mitre_tactic,
             log_source_type, event_status, bytes_transferred,
             failed_attempts, alert_score, raw_log_json)
        VALUES
            (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,PARSE_JSON(%s))
        """

        batch = [
            (e.event_id, e.event_datetime, e.user_id, e.username,
             e.department, e.host_id, e.hostname, e.ip_address,
             e.environment, e.os_type, e.threat_type, e.threat_category,
             e.severity, e.mitre_tactic, e.log_source_type, e.event_status,
             e.bytes_transferred, e.failed_attempts, e.alert_score,
             e.raw_log_json)
            for e in events
        ]

        cursor.executemany(insert_sql, batch)
        self.conn.commit()
        logger.info(f"Loaded {len(events)} events into Snowflake staging.")
        cursor.close()

    def close(self):
        if self.conn:
            self.conn.close()


# ─────────────────────────────────────────────
# Pipeline Orchestrator
# ─────────────────────────────────────────────

class CybersecETLPipeline:

    def __init__(self, snowflake_config: dict | None = None, batch_size: int = 200):
        self.extractor    = LogExtractor()
        self.transformer  = LogTransformer()
        self.loader       = SnowflakeLoader(snowflake_config or {})
        self.batch_size   = batch_size
        self.stats        = {
            "total_extracted": 0,
            "total_transformed": 0,
            "total_rejected": 0,
            "total_loaded": 0,
            "batches_processed": 0,
        }

    def run_batch(self, dry_run: bool = True):
        start = time.time()
        logger.info("=" * 60)
        logger.info("Starting Cybersecurity ETL Batch Run")
        logger.info("=" * 60)

        # Extract
        raw_events = self.extractor.extract_batch(self.batch_size)
        self.stats["total_extracted"] += len(raw_events)

        # Transform
        transformed, rejected = self.transformer.transform(raw_events)
        self.stats["total_transformed"] += len(transformed)
        self.stats["total_rejected"]    += len(rejected)

        # Load
        self.loader.connect()
        self.loader.load(transformed, dry_run=dry_run)
        self.loader.close()
        self.stats["total_loaded"]         += len(transformed)
        self.stats["batches_processed"]    += 1

        elapsed = round(time.time() - start, 2)
        logger.info(f"Batch complete in {elapsed}s | Stats: {self.stats}")

        # Print summary
        self._print_summary(transformed, rejected)
        return transformed, rejected

    def _print_summary(self, events: list[TransformedEvent], rejected: list):
        severity_counts = {}
        status_counts   = {}
        threat_counts   = {}
        for ev in events:
            severity_counts[ev.severity]     = severity_counts.get(ev.severity, 0) + 1
            status_counts[ev.event_status]   = status_counts.get(ev.event_status, 0) + 1
            threat_counts[ev.threat_type]    = threat_counts.get(ev.threat_type, 0) + 1

        print("\n" + "=" * 60)
        print("  ETL PIPELINE SUMMARY REPORT")
        print("=" * 60)
        print(f"  Extracted  : {self.stats['total_extracted']}")
        print(f"  Transformed: {self.stats['total_transformed']}")
        print(f"  Rejected   : {self.stats['total_rejected']}")
        print(f"  Rejected % : {100*self.stats['total_rejected']/max(self.stats['total_extracted'],1):.1f}%")
        print("\n  Severity Breakdown:")
        for sev in SEVERITY_LEVELS:
            print(f"    {sev:10}: {severity_counts.get(sev, 0)}")
        print("\n  Status Breakdown:")
        for status, cnt in sorted(status_counts.items()):
            print(f"    {status:12}: {cnt}")
        print("\n  Top 5 Threat Types:")
        for threat, cnt in sorted(threat_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"    {threat:30}: {cnt}")
        if rejected:
            print(f"\n  Rejected Events ({len(rejected)}):")
            for r in rejected[:5]:
                print(f"    {r['event_id']}: {r['errors']}")
        print("=" * 60 + "\n")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Snowflake config (replace with real credentials)
    SNOWFLAKE_CONFIG = {
        "user":        os.getenv("SF_USER",      "your_user"),
        "password":    os.getenv("SF_PASSWORD",  "your_password"),
        "account":     os.getenv("SF_ACCOUNT",   "your_account"),
        "warehouse":   os.getenv("SF_WAREHOUSE", "COMPUTE_WH"),
        "database":    os.getenv("SF_DATABASE",  "CYBERSEC_DB"),
        "schema":      os.getenv("SF_SCHEMA",    "RAW"),
    }

    pipeline = CybersecETLPipeline(
        snowflake_config=SNOWFLAKE_CONFIG,
        batch_size=500,
    )

    # Run in dry-run mode (set dry_run=False with real Snowflake credentials)
    pipeline.run_batch(dry_run=True)

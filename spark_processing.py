"""
============================================================
CYBERSECURITY LOG MONITORING SYSTEM
Apache Spark — Batch + Streaming Processing
============================================================
"""

import json
import random
import time
from datetime import datetime, timedelta
from dataclasses import dataclass

# ── PySpark (graceful fallback) ───────────────────────────
try:
    from pyspark.sql import SparkSession
    from pyspark.sql import functions as F
    from pyspark.sql.types import (
        StructType, StructField, StringType, IntegerType,
        FloatType, TimestampType, LongType, BooleanType
    )
    from pyspark.sql.window import Window
    HAS_SPARK = True
except ImportError:
    HAS_SPARK = False
    print("PySpark not installed — running simulation mode.")

# ─────────────────────────────────────────────
# Schema Definition
# ─────────────────────────────────────────────

LOG_SCHEMA_DICT = {
    "event_id":          "string",
    "timestamp":         "timestamp",
    "username":          "string",
    "src_ip":            "string",
    "dst_ip":            "string",
    "hostname":          "string",
    "environment":       "string",
    "threat_type":       "string",
    "severity":          "string",
    "alert_score":       "float",
    "bytes_transferred": "long",
    "failed_attempts":   "integer",
    "event_status":      "string",
    "department":        "string",
    "log_source":        "string",
    "mitre_tactic":      "string",
}

if HAS_SPARK:
    TYPE_MAP = {
        "string": StringType(), "float": FloatType(),
        "long": LongType(), "integer": IntegerType(),
        "timestamp": TimestampType(),
    }
    LOG_SCHEMA = StructType([
        StructField(k, TYPE_MAP[v], True)
        for k, v in LOG_SCHEMA_DICT.items()
    ])


# ─────────────────────────────────────────────
# Data Generator (replaces Kafka/file source)
# ─────────────────────────────────────────────

THREAT_TYPES  = ["Brute Force","SQL Injection","Port Scan","DDoS",
                 "Phishing","Malware","Privilege Escalation","Data Exfiltration"]
SEVERITIES    = ["LOW","MEDIUM","HIGH","CRITICAL"]
ENVIRONMENTS  = ["PROD","DEV","STAGING"]
DEPTS         = ["Engineering","Finance","HR","Legal","Operations"]
MITRE_TACTICS = ["Initial Access","Execution","Persistence","Privilege Escalation",
                 "Credential Access","Discovery","Lateral Movement","Exfiltration"]

def generate_log_records(n: int = 1000) -> list[dict]:
    base = datetime.utcnow()
    records = []
    for i in range(n):
        threat   = random.choice(THREAT_TYPES)
        severity = random.choices(SEVERITIES, weights=[40,30,20,10])[0]
        score    = round(random.uniform(0, 100), 2)
        records.append({
            "event_id":          f"EVT-{i:06d}",
            "timestamp":         (base - timedelta(seconds=random.randint(0, 86400))).isoformat(),
            "username":          f"user_{random.randint(1000, 9999)}",
            "src_ip":            ".".join(str(random.randint(1,254)) for _ in range(4)),
            "dst_ip":            ".".join(str(random.randint(1,254)) for _ in range(4)),
            "hostname":          f"host-{random.choice(['web','db','app'])}-{random.randint(1,20):02d}",
            "environment":       random.choice(ENVIRONMENTS),
            "threat_type":       threat,
            "severity":          severity,
            "alert_score":       score,
            "bytes_transferred": random.randint(0, 5_000_000),
            "failed_attempts":   random.randint(0, 100),
            "event_status":      "BLOCKED" if score>=80 else ("ALERTED" if score>=50 else "ALLOWED"),
            "department":        random.choice(DEPTS),
            "log_source":        random.choice(["Firewall","IDS","WAF","SIEM"]),
            "mitre_tactic":      random.choice(MITRE_TACTICS),
        })
    return records


# ─────────────────────────────────────────────
# Spark Batch Processing
# ─────────────────────────────────────────────

class CybersecSparkBatch:

    def __init__(self, app_name: str = "CybersecBatchProcessor"):
        if HAS_SPARK:
            self.spark = (SparkSession.builder
                .appName(app_name)
                .config("spark.sql.adaptive.enabled", "true")
                .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
                .config("spark.sql.shuffle.partitions", "200")
                .getOrCreate())
            self.spark.sparkContext.setLogLevel("WARN")
        else:
            self.spark = None

    def run_batch_analysis(self, records: list[dict]):
        if not HAS_SPARK:
            print("[SIMULATION] Running Spark Batch Analysis …")
            self._simulate_batch(records)
            return

        # Load into DataFrame
        df = self.spark.createDataFrame(records)
        df = df.withColumn("timestamp", F.to_timestamp("timestamp"))
        df.createOrReplaceTempView("security_events")
        df.cache()

        print(f"\n[SPARK BATCH] Total events: {df.count()}")

        # ── Analysis 1: Threat Distribution
        print("\n[1] Threat Distribution by Severity:")
        df.groupBy("threat_type", "severity") \
          .agg(F.count("*").alias("count"),
               F.avg("alert_score").alias("avg_score")) \
          .orderBy(F.desc("count")) \
          .show(15, truncate=False)

        # ── Analysis 2: Window Function — Rolling 1hr event count per user
        print("\n[2] Rolling Event Counts (Window Functions):")
        w = Window.partitionBy("username").orderBy("timestamp") \
                  .rangeBetween(-3600, 0)   # 1-hour window
        rolling_df = df.withColumn(
            "events_last_1hr", F.count("event_id").over(w)
        ).withColumn(
            "max_score_1hr", F.max("alert_score").over(w)
        )
        rolling_df.select(
            "username", "timestamp", "threat_type",
            "events_last_1hr", "max_score_1hr"
        ).orderBy(F.desc("events_last_1hr")).show(10, truncate=False)

        # ── Analysis 3: Top Risky Users
        print("\n[3] Top 10 High-Risk Users:")
        user_risk = df.groupBy("username", "department") \
            .agg(
                F.count("*").alias("total_events"),
                F.sum("failed_attempts").alias("total_failures"),
                F.avg("alert_score").alias("avg_risk_score"),
                F.sum(F.when(F.col("severity")=="CRITICAL",1).otherwise(0)).alias("critical_count")
            ) \
            .withColumn("composite_risk",
                F.col("avg_risk_score") * 0.4 +
                F.col("total_failures") * 0.3 +
                F.col("critical_count") * 30.0
            ) \
            .orderBy(F.desc("composite_risk"))
        user_risk.show(10, truncate=False)

        # ── Analysis 4: Hourly Trend
        print("\n[4] Hourly Event Trend:")
        df.withColumn("hour", F.date_trunc("hour", "timestamp")) \
          .groupBy("hour", "environment") \
          .agg(F.count("*").alias("events"),
               F.sum(F.when(F.col("event_status")=="BLOCKED",1).otherwise(0)).alias("blocked")) \
          .orderBy("hour") \
          .show(24, truncate=False)

        # ── Analysis 5: Anomaly Detection with z-score
        print("\n[5] Anomaly Detection (Z-Score > 2):")
        avg_score = df.agg(F.avg("alert_score")).collect()[0][0]
        std_score = df.agg(F.stddev("alert_score")).collect()[0][0]
        anomalies = df.filter(
            (F.col("alert_score") - avg_score) / std_score > 2.0
        ).select("event_id","username","threat_type","alert_score","severity","event_status")
        anomalies.show(10, truncate=False)

        # ── Write Parquet (partitioned)
        output_path = "/tmp/cybersec_processed"
        df.repartition("environment", "severity") \
          .write \
          .mode("overwrite") \
          .partitionBy("environment", "severity") \
          .parquet(output_path)
        print(f"\n[SPARK] Output written to: {output_path}")

    def _simulate_batch(self, records: list[dict]):
        """Fallback simulation when Spark isn't installed."""
        from collections import Counter

        threat_counts  = Counter(r["threat_type"]   for r in records)
        severity_counts= Counter(r["severity"]       for r in records)
        status_counts  = Counter(r["event_status"]   for r in records)
        dept_failures  = {}
        for r in records:
            dept_failures[r["department"]] = (
                dept_failures.get(r["department"], 0) + r["failed_attempts"]
            )

        print("\n" + "="*60)
        print("  SPARK BATCH SIMULATION REPORT")
        print("="*60)
        print(f"  Total Events: {len(records)}")
        print("\n  Threat Type Distribution:")
        for t, c in sorted(threat_counts.items(), key=lambda x: -x[1]):
            bar = "█" * (c // 10)
            print(f"    {t:30} | {c:4d} | {bar}")
        print("\n  Severity Breakdown:")
        for s, c in severity_counts.items():
            print(f"    {s:10}: {c}")
        print("\n  Event Status:")
        for st, c in status_counts.items():
            print(f"    {st:12}: {c}")
        print("\n  Department Failures (Top 5):")
        for dept, f in sorted(dept_failures.items(), key=lambda x: -x[1])[:5]:
            print(f"    {dept:20}: {f}")
        critical = [r for r in records if r["severity"] == "CRITICAL"]
        print(f"\n  Critical Events: {len(critical)}")
        high_score = sorted(records, key=lambda r: -r["alert_score"])[:5]
        print("  Top Alert Scores:")
        for r in high_score:
            print(f"    {r['event_id']} | {r['threat_type']:25} | Score: {r['alert_score']:.1f}")
        print("="*60)


# ─────────────────────────────────────────────
# Spark Streaming (Structured Streaming)
# ─────────────────────────────────────────────

class CybersecSparkStreaming:
    """Simulates real-time Spark Structured Streaming from Kafka."""

    KAFKA_CONFIG = """
    # Kafka + Spark Structured Streaming Config (for production)
    # ─────────────────────────────────────────
    # df_stream = spark.readStream \\
    #     .format("kafka") \\
    #     .option("kafka.bootstrap.servers", "broker:9092") \\
    #     .option("subscribe", "cybersec-logs") \\
    #     .option("startingOffsets", "latest") \\
    #     .load()
    #
    # parsed = df_stream.select(
    #     F.from_json(F.col("value").cast("string"), LOG_SCHEMA).alias("data")
    # ).select("data.*")
    #
    # query = parsed.writeStream \\
    #     .outputMode("append") \\
    #     .format("delta") \\
    #     .option("checkpointLocation", "/checkpoints/cybersec") \\
    #     .trigger(processingTime="30 seconds") \\
    #     .start("/data/cybersec_streaming")
    """

    def simulate_stream(self, duration_seconds: int = 10, events_per_second: int = 50):
        print("\n" + "="*60)
        print("  SPARK STREAMING SIMULATION (Real-time)")
        print("="*60)
        print(f"  Simulating {events_per_second} events/sec for {duration_seconds}s\n")

        total   = 0
        blocked = 0
        alerts  = 0
        critical= 0
        window_counts = {}   # threat_type → count in last window

        start = time.time()
        while time.time() - start < duration_seconds:
            batch = generate_log_records(events_per_second)
            total += len(batch)
            for ev in batch:
                if ev["event_status"] == "BLOCKED":  blocked  += 1
                if ev["event_status"] == "ALERTED":  alerts   += 1
                if ev["severity"] == "CRITICAL":      critical += 1
                wk = ev["threat_type"]
                window_counts[wk] = window_counts.get(wk, 0) + 1

            elapsed = time.time() - start
            top_threat = max(window_counts, key=window_counts.get)
            print(
                f"  [{elapsed:4.1f}s] Events: {total:6d} | "
                f"Blocked: {blocked:5d} | Critical: {critical:4d} | "
                f"Top Threat: {top_threat}"
            )
            time.sleep(1)

        print("\n  Stream Summary:")
        print(f"    Total Processed : {total}")
        print(f"    Blocked         : {blocked} ({100*blocked/total:.1f}%)")
        print(f"    Alerted         : {alerts}  ({100*alerts/total:.1f}%)")
        print(f"    Critical Events : {critical}")
        print(f"\n  Threat Window Counts (final):")
        for threat, cnt in sorted(window_counts.items(), key=lambda x: -x[1]):
            print(f"    {threat:30}: {cnt}")
        print("="*60)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

if __name__ == "__main__":
    records = generate_log_records(2000)

    print("\n" + "█"*60)
    print("  CYBERSECURITY SPARK PROCESSING")
    print("█"*60)

    # Batch
    batch_processor = CybersecSparkBatch()
    batch_processor.run_batch_analysis(records)

    # Streaming simulation
    stream_processor = CybersecSparkStreaming()
    stream_processor.simulate_stream(duration_seconds=5, events_per_second=100)

    print("\nDone! See Kafka+Spark config in CybersecSparkStreaming.KAFKA_CONFIG")

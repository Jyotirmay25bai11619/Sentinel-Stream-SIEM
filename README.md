# SentinelStream

[![Java](https://img.shields.io/badge/Java-11%2B-blue.svg)](https://www.oracle.com/java/)
[![Maven](https://img.shields.io/badge/Maven-Build-green.svg)](https://maven.apache.org/)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%7C%20H2-orange.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

SentinelStream is a high-throughput, concurrent Security Information and Event Management (SIEM) log processing and threat detection engine written in Java. It models the core backend mechanics of modern security monitoring pipelines like Splunk and CrowdStrike, processing high-volume telemetry streams in real time.

---

## Architecture Overview

SentinelStream implements a multithreaded Producer-Consumer pipeline with bounded queues, backpressure handling, and hybrid data persistence:

```
                          server_traffic.log
                                  │
                                  │ Character stream (BufferedReader / UTF-8)
                                  ▼
                             LogProducer
                                  │ (Catches & isolates MalformedTelemetryException)
                                  ▼
                           SharedLogBuffer
                      (Bounded BlockingQueue)
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
    LogConsumer #1           LogConsumer #2           LogConsumer #N
   (Isolated Rules)         (Isolated Rules)         (Isolated Rules)
         │                        │                        │
         ├────────────────────────┴────────────────────────┤
         │                                                 │
   Batched Records                                   Rule Detections
         ▼                                                 ▼
TelemetryBatchWriter (JDBC)                       IncidentReportDAO (JPA)
   Raw telemetry rows                                Relational incidents
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  ▼
                         PostgreSQL / H2
```

### Key Engineering Highlights
* **High-Throughput Concurrency:** Fixed thread pool draining a bounded `SharedLogBuffer` (`BlockingQueue`) providing natural backpressure against fast log producers.
* **Fault-Tolerant Parsing:** Resilient line-by-line validation (`MalformedTelemetryException`) ensures corrupted telemetry lines never interrupt pipeline ingestion.
* **Thread-Isolated Detection State:** Each consumer thread holds its own reflection-loaded `SecurityRule` instances to eliminate lock contention on sliding windows.
* **Hybrid Storage Architecture:** 
  * **Raw Fast-Path:** Pure JDBC batch inserts (`PreparedStatement` batches) for maximum write throughput into `raw_telemetry`.
  * **Analyst Incident Store:** Relational JPA / Hibernate persistence (`IncidentReport` ↔ `ThreatOrigin`) with thread-safe origin resolution and JPQL query support.
* **Zero-Config Embedded Fallback:** Automatically falls back to in-memory H2 database if a local PostgreSQL instance is not detected.

---

## Active Threat Detection Rules

| Detector | Category | Threat Level | Detection Mechanism |
|---|---|---|---|
| `BruteForceDetector` | Auth Abuse | `HIGH` / `CRITICAL` | Evaluates sliding time window of consecutive `LOGIN_FAILED` events per IP using a stateful `Stack`. |
| `DataExfiltrationDetector` | Data Theft | `CRITICAL` | Flags high-frequency bursts of `DATA_TRANSFER` and `FILE_ACCESS` events exceeding volume thresholds. |
| `SqlInjectionDetector` | Web Application | `CRITICAL` | Regex signature matching for union queries, tautologies (`' OR '1'='1`), and DDL statements. |
| `PathTraversalDetector` | Filesystem | `HIGH` | Path normalization and directory stack traversal simulation to detect attempts to access files above root. |

---

## Project Structure

```
SIEM--main/
├── .gitignore
├── build.bat                            # Windows build script (auto-detects Maven)
├── run.bat                              # Windows execution script
├── LICENSE
├── README.md                            # Main project documentation
├── Concepts/
│   └── Syllabus implementation.md       # Architectural mapping guide
└── sentinelstream/
    ├── pom.xml                          # Maven build definition & dependencies
    ├── sql/
    │   └── init.sql                     # PostgreSQL schema for raw_telemetry
    └── src/
        ├── main/
        │   ├── java/com/sentinelstream/
        │   │   ├── Main.java            # Pipeline wiring & orchestration
        │   │   ├── annotation/          # Custom security metadata annotations
        │   │   ├── concurrency/         # Producer, consumer, and shared buffer
        │   │   ├── config/              # Database connection pool manager
        │   │   ├── exception/           # Checked telemetry exceptions
        │   │   ├── model/               # Immutable telemetry records & enums
        │   │   ├── persistence/         # Hybrid JDBC & JPA/Hibernate layers
        │   │   ├── rules/               # Pluggable security rule detectors
        │   │   └── util/                # Log parser & mock data generator
        │   └── resources/
        │       ├── application.properties
        │       └── META-INF/persistence.xml
        └── test/                        # Unit tests for rule detectors
```

---

## Quickstart Guide

### Prerequisites
* **Java:** JDK 11 or higher
* **Maven:** 3.6+ (Optional if using `build.bat` with IntelliJ IDEA installed)
* **PostgreSQL:** Optional (embedded H2 is used automatically if unavailable)

### 1. Build the Project
Using the automated build script:
```cmd
build.bat
```
Or directly with Maven:
```bash
cd sentinelstream
mvn clean install
cd ..
```

### 2. Run the Engine
Using the execution script:
```cmd
run.bat
```
Or run the shaded fat JAR:
```bash
java -jar sentinelstream/target/sentinel-stream.jar
```
*Note: If `server_traffic.log` is not present, the application will automatically generate mock data on first launch.*

---

## Database Configuration

By default, the application connects to a local PostgreSQL instance and gracefully falls back to embedded H2 if PostgreSQL is offline.

To use your local PostgreSQL server:
1. Create the database:
   ```sql
   CREATE DATABASE sentinel_stream_db;
   ```
2. Run `sentinelstream/sql/init.sql` to initialize the `raw_telemetry` table.
3. Configure credentials in `sentinelstream/src/main/resources/application.properties`:
   ```properties
   db.url=jdbc:postgresql://localhost:5432/sentinel_stream_db
   db.user=postgres
   db.password=your_password
   db.pool.size=8
   ```

---

## Pipeline Tuning

Adjust pipeline throughput in `application.properties`:

| Property | Default | Description |
|---|---|---|
| `pipeline.consumer.threads` | `4` | Worker threads processing and analyzing telemetry |
| `pipeline.buffer.capacity` | `10000` | Bounded queue capacity between producer and consumers |
| `db.pool.size` | `8` | Pooled connections for JDBC batch writes |
| `mockdata.target.size.mb` | `50` | File size for synthetic mock telemetry generation |

---

## Verification & Queries

Verify results in PostgreSQL or H2 console after a run:

```sql
-- Count total raw telemetry records ingested via JDBC fast-path:
SELECT COUNT(*) FROM raw_telemetry;

-- Review prioritized security incidents detected by the rule engine:
SELECT id, rule_name, severity, detected_at, summary 
FROM incident_reports 
ORDER BY severity DESC, detected_at DESC;

-- Correlate incidents to specific threat origin IPs:
SELECT ir.rule_name, ir.severity, ir.summary, t.ip_address, t.first_seen
FROM incident_reports ir
JOIN threat_origins t ON ir.threat_origin_id = t.id
WHERE t.ip_address = '192.168.1.45';
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

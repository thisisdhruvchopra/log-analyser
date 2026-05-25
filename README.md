# HTTP Honeypot Log Analyser

A modular Python-based threat intelligence toolkit for analysing HTTP honeypot logs. Built for real-world deployment as part of a deception technology engagement at **Bhilai Steel Plant (SAIL BSP)** — a critical industrial infrastructure client.

Each script is standalone and targets a specific aspect of attacker behaviour: event classification, credential harvesting, geolocation, endpoint targeting, and temporal analysis.

---

## Module Overview

| Script | Purpose |
|---|---|
| `analysis.py` | Classifies log events by type and severity |
| `geo_analysis.py` | Maps attacking IPs to countries using GeoIP |
| `endpoint.py` | Identifies which endpoints are being targeted and by whom |
| `passwords.py` | Extracts and ranks credential (password) attempts |
| `usernames.py` | Extracts and ranks username attempts |
| `summary.py` | Aggregates outputs into a single attack summary |
| `split_logs_by_date.py` | Slices logs into a specific date range |
| `remove_localhost_logs.py` | Cleans localhost/loopback entries from raw logs |

---

## Requirements

- Python 3.8+
- [`maxminddb`](https://pypi.org/project/maxminddb/) — for GeoIP lookups
- `GeoLite2-Country.mmdb` — MaxMind GeoLite2 database (included in repo)

Install dependency:
```bash
pip install maxminddb
```

---

## Usage

Each script is run independently and prompts for input interactively.

### 1. Clean the logs first

Remove loopback/localhost noise before any analysis:
```bash
python remove_localhost_logs.py
# Input: your raw .log file
# Output: <filename>_no_localhost.log
```

### 2. Slice by date range (optional)

Focus analysis on a specific week or reporting period:
```bash
python split_logs_by_date.py
# Accepts formats: YYYY-MM-DD, DD-MM-YYYY, YYYY/MM/DD, etc.
# Output: <filename>_<start>_to_<end>.log
```

### 3. Classify events by type and severity
```bash
python analysis.py
# Output: analysis_event_statistics.csv, analysis_severity_breakdown.csv
```

**Event types detected:**

| Event | Severity | Examples |
|---|---|---|
| `command_execution_attempts` | High | shell pipes, backtick execution, `$()` |
| `exploit_attempts` | High | `/etc/passwd`, `../`, `/bin/sh`, `/cmd=` |
| `attack_log_attempts` | High | Bad request version, HTTP 400 |
| `scan_attempts` | Medium | `/admin`, `/wp-`, `.env`, `.git`, `/phpmyadmin` |
| `connect_attempts` | Low | Standard GET/POST/HEAD requests |

### 4. Geolocate attacking IPs
```bash
python geo_analysis.py
# Output: attacking_countries.csv, attacking_ips_country.csv
```

Only lines matching attack patterns are counted — consistent with `analysis.py`.

### 5. Extract credential attempts
```bash
python passwords.py   # Top 50 passwords attempted
python usernames.py   # Top 50 usernames attempted
# Output: <filename>_top_passwords.csv / <filename>_top_usernames.csv
```

Extracts from POST body parameters (`password=`, `pass=`, `username=`, `user=`, etc.). Filters out path traversal and exploit garbage automatically.

### 6. Analyse endpoint targeting
```bash
python endpoint.py
# Prompts for a specific endpoint e.g. /admin, /cgi-bin
# Output: endpoint.csv (IP → hit count, sorted descending)
```

### 7. Generate full attack summary
```bash
python summary.py
# Requires: attacking_countries.csv and attacking_ips_country.csv to exist
# Output: Top date, top country, top IP, most targeted endpoint
```

---

## Sample Summary Output

```
=== BSP Aggregated Attack Summary ===

Most Traffic / Attacks On
14 May 2025 (3,241 events)

Most Attacking Country
China (1,872 events)

Most Attacking IP
45.xxx.xxx.xxx (304 events)

Most Targeted Endpoint
/admin (918 hits)
```

---

## Attack Detection Logic

All scripts share a consistent regex-based detection engine. A log line is classified as an attack if it matches any of the following patterns:

- **Command injection**: `;cmd`, `|cmd`, `` `cmd` ``, `$(cmd)`
- **Path traversal / exploits**: `../`, `/etc/passwd`, `/proc/self`, `/bin/sh`
- **CMS / admin scanning**: `/wp-`, `/phpmyadmin`, `/manager/html`, `/HNAP1`
- **Sensitive file probing**: `.env`, `.git`, `/cgi-bin`
- **Malformed HTTP**: `Bad request version`, `code 400`, `invalid HTTP version`

ANSI escape sequences are stripped from all log lines before processing to handle coloured terminal output formats.

---

## Notes

- Logs are expected in IST (UTC+5:30) timezone for date-based slicing.
- The `GeoLite2-Country.mmdb` database must be present in the working directory for `geo_analysis.py` to function.
- All CSVs are UTF-8 encoded and compatible with Excel and Google Sheets.
- Scripts are designed for **weekly threat intel reporting** workflows.

---

## Author

**Dhruv Chopra**  
Associate – Deception Technology, C3iHub @ IIT Kanpur  
[github.com/thisisdhruvchopra](https://github.com/thisisdhruvchopra)

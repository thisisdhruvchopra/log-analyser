#!/usr/bin/env python3

import re
import csv
import os
import sys
from collections import Counter
from datetime import datetime

# ================= ATTACK FILTER (SAME AS BEFORE) =================

ATTACK_PATTERNS = [
    r';\s*\w+',
    r'\|\s*\w+',
    r'`[^`]+`',
    r'\$\([^)]+\)',

    r'\.\./',
    r'/etc/passwd',
    r'/proc/self',
    r'/bin/sh',
    r'/cmd=',
    r'/shell',
    r'/auto\.php',

    r'Bad request version',
    r'code 400',
    r'invalid HTTP version',

    r'/admin',
    r'/login',
    r'\.git',
    r'\.env',
    r'/wp-',
    r'/phpmyadmin',
    r'/manager/html',
    r'/cgi-bin',
    r'/HNAP1',
]

DATE_REGEX = re.compile(r'^(\d{4}-\d{2}-\d{2})')
ENDPOINT_REGEX = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE)\s+([^ ]+)')
ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


# ================= HELPERS =================

def strip_ansi(text):
    return ANSI_ESCAPE_REGEX.sub('', text)


def is_attack(line):
    for p in ATTACK_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            return True
    return False


def pretty_date(date_str):
    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d %b %Y")


# ================= CORE =================

def analyze_log(log_file):
    date_counter = Counter()
    endpoint_counter = Counter()

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = strip_ansi(raw_line)

            if not is_attack(line):
                continue

            date_match = DATE_REGEX.search(line)
            if date_match:
                date_counter[date_match.group(1)] += 1

            endpoint_match = ENDPOINT_REGEX.search(line)
            if endpoint_match:
                endpoint_counter[endpoint_match.group(1)] += 1

    return date_counter, endpoint_counter


def top_from_csv(csv_file, key_col, count_col):
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        row = next(reader)
        return row[key_col], int(row[count_col])


# ================= MAIN =================

def main():
    print("\n=== BSP Aggregated Attack Summary ===\n")

    log_file = input("Enter log file name: ").strip()
    if not os.path.isfile(log_file):
        print("ERROR: Log file not found.")
        sys.exit(1)

    country_csv = "attacking_countries.csv"
    ip_csv = "attacking_ips_country.csv"

    if not os.path.isfile(country_csv) or not os.path.isfile(ip_csv):
        print("ERROR: Required CSV files not found.")
        sys.exit(1)

    # Log-based analysis
    date_counts, endpoint_counts = analyze_log(log_file)

    top_date, top_date_count = date_counts.most_common(1)[0]
    top_endpoint, top_endpoint_count = endpoint_counts.most_common(1)[0]

    # CSV-based analysis
    top_country, top_country_count = top_from_csv(
        country_csv, "Country", "Total_Count"
    )

    top_ip, top_ip_count = top_from_csv(
        ip_csv, "IP", "Count"
    )

    # -------- FINAL OUTPUT --------
    print("Most Traffic / Attacks On")
    print(f"{pretty_date(top_date)} ({top_date_count} events)\n")

    print("Most Attacking Country")
    print(f"{top_country} ({top_country_count} events)\n")

    print("Most Attacking IP")
    print(f"{top_ip} ({top_ip_count} events)\n")

    print("Most Targeted Endpoint")
    print(f"{top_endpoint} ({top_endpoint_count} hits)\n")


if __name__ == "__main__":
    main()

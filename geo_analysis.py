#!/usr/bin/env python3

import re
import csv
import os
import sys
from collections import Counter, defaultdict
import maxminddb

# ================= CONFIG =================

GEO_DB = "GeoLite2-Country.mmdb"

ATTACK_EVENT_PATTERNS = [
    # command execution
    r';\s*\w+',
    r'\|\s*\w+',
    r'`[^`]+`',
    r'\$\([^)]+\)',

    # exploits
    r'\.\./',
    r'/etc/passwd',
    r'/proc/self',
    r'/bin/sh',
    r'/cmd=',
    r'/shell',
    r'/auto\.php',

    # attack logs
    r'Bad request version',
    r'code 400',
    r'invalid HTTP version',

    # scans
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

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]', re.IGNORECASE)

# ================= HELPERS =================

def strip_ansi(text):
    return ANSI_ESCAPE_REGEX.sub('', text)


def is_attack(line):
    for pattern in ATTACK_EVENT_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def get_country(reader, ip):
    try:
        res = reader.get(ip)
        if res and "country" in res and "names" in res["country"]:
            return res["country"]["names"].get("en", "Unknown")
    except Exception:
        pass
    return "Unknown"


# ================= CORE =================

def analyze_geo_attacks(log_file):
    country_counter = Counter()
    ip_counter = Counter()
    ip_country_map = {}

    with maxminddb.open_database(GEO_DB) as reader:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = strip_ansi(raw_line)

                if not is_attack(line):
                    continue  # STRICT consistency filter

                ip_match = IP_REGEX.search(line)
                if not ip_match:
                    continue

                ip = ip_match.group()
                country = get_country(reader, ip)

                country_counter[country] += 1
                ip_counter[ip] += 1
                ip_country_map[ip] = country

    return country_counter, ip_counter, ip_country_map


# ================= MAIN =================

def main():
    print("\n=== BSP Geo Attack Analysis ===\n")

    if not os.path.isfile(GEO_DB):
        print(f"ERROR: GeoIP DB not found: {GEO_DB}")
        sys.exit(1)

    log_file = input("Enter log file name: ").strip()
    if not os.path.isfile(log_file):
        print("ERROR: Log file does not exist.")
        sys.exit(1)

    country_counts, ip_counts, ip_country = analyze_geo_attacks(log_file)

    # -------- COUNTRY CSV --------
    country_csv = "attacking_countries.csv"
    with open(country_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["S.No", "Country", "Total_Count"])
        for i, (country, count) in enumerate(country_counts.most_common(), 1):
            writer.writerow([i, country, count])

    # -------- IP CSV --------
    ip_csv = "attacking_ips_country.csv"
    with open(ip_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["S.No", "IP", "Count", "Country"])
        for i, (ip, count) in enumerate(ip_counts.most_common(), 1):
            writer.writerow([i, ip, count, ip_country.get(ip, "Unknown")])

    # -------- CONSISTENCY CHECK --------
    print("Consistency Check")
    print("-----------------")
    print(f"Total Attacks (Countries): {sum(country_counts.values())}")
    print(f"Total Attacks (IPs)       : {sum(ip_counts.values())}")

    print("\nCSV files exported:")
    print(f"- {country_csv}")
    print(f"- {ip_csv}")


if __name__ == "__main__":
    main()

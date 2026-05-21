#!/usr/bin/env python3

import re
import csv
import os
import sys
from collections import Counter

# ================= EVENT DETECTION (ORDER MATTERS) =================
# First match wins → exactly ONE event per line

EVENT_RULES = [
    ("command_execution_attempts", [
        r';\s*\w+',
        r'\|\s*\w+',
        r'`[^`]+`',
        r'\$\([^)]+\)',
    ]),

    ("exploit_attempts", [
        r'\.\./',
        r'/etc/passwd',
        r'/proc/self',
        r'/bin/sh',
        r'/cmd=',
        r'/shell',
        r'/auto\.php',
    ]),

    ("attack_log_attempts", [
        r'Bad request version',
        r'code 400',
        r'invalid HTTP version',
    ]),

    ("scan_attempts", [
        r'/admin',
        r'/login',
        r'\.git',
        r'\.env',
        r'/wp-',
        r'/phpmyadmin',
        r'/manager/html',
        r'/cgi-bin',
        r'/HNAP1',
    ]),

    # fallback – must be LAST
    ("connect_attempts", [
        r'"GET ',
        r'"HEAD ',
        r'"POST ',
    ]),
]

# ================= SEVERITY MAP =================

SEVERITY_MAP = {
    "command_execution_attempts": "High",
    "exploit_attempts": "High",
    "attack_log_attempts": "High",
    "scan_attempts": "Medium",
    "connect_attempts": "Low",
}

ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]', re.IGNORECASE)


# ================= HELPERS =================
def strip_ansi(text):
    return ANSI_ESCAPE_REGEX.sub('', text)


def classify_event(line):
    """
    Returns exactly ONE event label or None
    """
    for event, patterns in EVENT_RULES:
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return event
    return None


# ================= CORE ANALYSIS =================
def analyze_log(input_file):
    event_counter = Counter()
    severity_counter = Counter()
    total_events = 0

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = strip_ansi(raw_line)

            event = classify_event(line)
            if not event:
                continue  # not an event at all

            severity = SEVERITY_MAP[event]

            event_counter[event] += 1
            severity_counter[severity] += 1
            total_events += 1

    return event_counter, severity_counter, total_events


# ================= MAIN =================
def main():
    print("\n=== BSP Unified Log Analysis ===\n")

    input_file = input("Enter log file name: ").strip()
    if not os.path.isfile(input_file):
        print("ERROR: File does not exist.")
        sys.exit(1)

    event_stats, severity_stats, total = analyze_log(input_file)

    # -------- EVENT STATISTICS CSV --------
    event_csv = "analysis_event_statistics.csv"
    with open(event_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["S. No.", "Event Label", "Event Count"])
        for i, (event, count) in enumerate(event_stats.items(), 1):
            writer.writerow([i, event, count])

    # -------- SEVERITY CSV --------
    severity_csv = "analysis_severity_breakdown.csv"
    with open(severity_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity Level", "Count"])
        for sev in ["Low", "Medium", "High"]:
            writer.writerow([sev, severity_stats.get(sev, 0)])

    # -------- CONSISTENCY CHECK --------
    print("Consistency Check")
    print("-----------------")
    print(f"Total Events            : {total}")
    print(f"Sum(Event Statistics)   : {sum(event_stats.values())}")
    print(f"Sum(Severity Breakdown) : {sum(severity_stats.values())}")

    print("\nCSV files exported:")
    print(f"- {event_csv}")
    print(f"- {severity_csv}")


if __name__ == "__main__":
    main()

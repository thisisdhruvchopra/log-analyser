#!/usr/bin/env python3

import re
import os
import sys
import csv
from collections import Counter

# Explicit username keys ONLY
USERNAME_REGEX = re.compile(
    r'\b(?:username|user|login)\s*=\s*([A-Za-z0-9._-]{1,64})',
    re.IGNORECASE
)

ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


def strip_ansi(text):
    return ANSI_ESCAPE_REGEX.sub('', text)


def is_valid_username(value):
    # Reject obvious exploit / path garbage
    return not any(x in value for x in ['/', '\\', '..', '&', '?', '='])


def main():
    print("\n=== BSP HTTP Username Extractor ===\n")

    input_file = input("Enter log file name: ").strip()
    if not os.path.isfile(input_file):
        print("ERROR: File does not exist.")
        sys.exit(1)

    counter = Counter()

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = strip_ansi(raw_line)

            for match in USERNAME_REGEX.findall(line):
                if is_valid_username(match):
                    counter[match.lower()] += 1

    if not counter:
        print("No valid username attempts found.")
        return

    csv_file = f"{os.path.splitext(input_file)[0]}_top_usernames.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["S. No.", "Username", "Count"])
        for i, (u, c) in enumerate(counter.most_common(50), 1):
            writer.writerow([i, u, c])

    print("\nS. No., Username, Count")
    for i, (u, c) in enumerate(counter.most_common(50), 1):
        print(f"{i}, {u}, {c}")

    print(f"\nCSV exported: {csv_file}")


if __name__ == "__main__":
    main()

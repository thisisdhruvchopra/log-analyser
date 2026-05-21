#!/usr/bin/env python3

import re
import os
import sys
import csv
from collections import Counter

# Explicit password keys ONLY
PASSWORD_REGEX = re.compile(
    r'\b(?:password|pass|pwd)\s*=\s*([A-Za-z0-9!@#$%^*()_+.-]{1,64})',
    re.IGNORECASE
)

ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


def strip_ansi(text):
    return ANSI_ESCAPE_REGEX.sub('', text)


def is_valid_password(value):
    # Reject tokens, paths, payloads
    return not any(x in value for x in ['/', '\\', '..', '&', '?', '='])


def main():
    print("\n=== BSP HTTP Password Extractor ===\n")

    input_file = input("Enter log file name: ").strip()
    if not os.path.isfile(input_file):
        print("ERROR: File does not exist.")
        sys.exit(1)

    counter = Counter()

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = strip_ansi(raw_line)

            for match in PASSWORD_REGEX.findall(line):
                if is_valid_password(match):
                    counter[match] += 1

    if not counter:
        print("No valid password attempts found.")
        return

    csv_file = f"{os.path.splitext(input_file)[0]}_top_passwords.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["S. No.", "Password", "Count"])
        for i, (p, c) in enumerate(counter.most_common(50), 1):
            writer.writerow([i, p, c])

    print("\nS. No., Password, Count")
    for i, (p, c) in enumerate(counter.most_common(50), 1):
        print(f"{i}, {p}, {c}")

    print(f"\nCSV exported: {csv_file}")


if __name__ == "__main__":
    main()

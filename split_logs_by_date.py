#!/usr/bin/env python3

import re
from datetime import datetime, timezone, timedelta
import sys
import os

# ================= CONFIG =================
IST = timezone(timedelta(hours=5, minutes=30))

TIMESTAMP_REGEX = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) IST'
)

ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

SUPPORTED_DATE_FORMATS = [
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d-%m-%Y",
    "%d/%m/%Y",
    "%Y%m%d",
]

# ================= HELPERS =================
def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_REGEX.sub('', text)


def parse_log_timestamp(line: str):
    """
    Extract timestamp from log line.
    Returns timezone-aware datetime or None.
    """
    match = TIMESTAMP_REGEX.search(line)
    if not match:
        return None

    try:
        dt = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=IST)
    except ValueError:
        return None


def parse_user_date(date_str: str):
    """
    Parse user-supplied date using multiple formats.
    """
    for fmt in SUPPORTED_DATE_FORMATS:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


# ================= CORE LOGIC =================
def split_logs_by_date_range(input_file, start_date, end_date):
    start_dt = start_date.replace(hour=0, minute=0, second=0, tzinfo=IST)
    end_dt = end_date.replace(hour=23, minute=59, second=59, tzinfo=IST)

    if start_dt > end_dt:
        print("ERROR: Start date is after end date.")
        sys.exit(1)

    output_file = (
        f"{os.path.splitext(input_file)[0]}_"
        f"{start_dt.date()}_to_{end_dt.date()}.log"
    )

    total = matched = skipped = 0

    with open(input_file, "r", encoding="utf-8", errors="replace") as infile, \
         open(output_file, "w", encoding="utf-8", errors="replace") as outfile:

        for raw_line in infile:
            total += 1

            # Clean ANSI for parsing only
            clean_line = strip_ansi(raw_line)

            ts = parse_log_timestamp(clean_line)
            if ts is None:
                skipped += 1
                continue

            if start_dt <= ts <= end_dt:
                outfile.write(raw_line)
                matched += 1

    print("\nLog slicing completed successfully")
    print("---------------------------------")
    print(f"Input file  : {input_file}")
    print(f"Output file : {output_file}")
    print(f"Date range  : {start_dt.date()} → {end_dt.date()} (IST)")
    print(f"Time window : 00:00:00 → 23:59:59")
    print(f"Lines read  : {total}")
    print(f"Matched     : {matched}")
    print(f"Skipped     : {skipped}")


# ================= MAIN =================
def main():
    print("\n=== BSP Log Date Range Slicer ===\n")

    input_file = input("Enter log file name: ").strip()
    if not os.path.isfile(input_file):
        print("ERROR: File does not exist.")
        sys.exit(1)

    print("\nAccepted date formats:")
    print("  YYYY-MM-DD")
    print("  YYYY/MM/DD")
    print("  DD-MM-YYYY")
    print("  DD/MM/YYYY")
    print("  YYYYMMDD\n")

    start_input = input("Enter START date: ").strip()
    end_input = input("Enter END date  : ").strip()

    start_date = parse_user_date(start_input)
    end_date = parse_user_date(end_input)

    if not start_date or not end_date:
        print("ERROR: Invalid date format.")
        sys.exit(1)

    split_logs_by_date_range(input_file, start_date, end_date)


if __name__ == "__main__":
    main()

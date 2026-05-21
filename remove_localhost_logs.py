#!/usr/bin/env python3

import os
import sys
import re

# ================= CONFIG =================
LOCALHOST_REGEX = re.compile(
    r'\b(127\.0\.0\.1|::1)\b'
)

ANSI_ESCAPE_REGEX = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


# ================= HELPERS =================
def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_REGEX.sub('', text)


# ================= CORE LOGIC =================
def remove_localhost_entries(input_file):
    output_file = f"{os.path.splitext(input_file)[0]}_no_localhost.log"

    total = removed = kept = 0

    with open(input_file, "r", encoding="utf-8", errors="replace") as infile, \
         open(output_file, "w", encoding="utf-8", errors="replace") as outfile:

        for raw_line in infile:
            total += 1
            clean_line = strip_ansi(raw_line)

            if LOCALHOST_REGEX.search(clean_line):
                removed += 1
                continue

            outfile.write(raw_line)
            kept += 1

    print("\nLocalhost filtering completed")
    print("-----------------------------")
    print(f"Input file         : {input_file}")
    print(f"Output file        : {output_file}")
    print(f"Total lines read   : {total}")
    print(f"Localhost removed  : {removed}")
    print(f"Lines kept         : {kept}")


# ================= MAIN =================
def main():
    print("\n=== BSP Localhost Log Cleaner ===\n")

    input_file = input("Enter log file name: ").strip()
    if not os.path.isfile(input_file):
        print("ERROR: File does not exist.")
        sys.exit(1)

    remove_localhost_entries(input_file)


if __name__ == "__main__":
    main()

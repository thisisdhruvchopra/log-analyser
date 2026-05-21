import re
import csv

def extract_ips_for_endpoint(log_file, endpoint):
    ip_counts = {}
    total_hits = 0

    # regex to extract IP and request
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^"]+)')

    # regex to remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # remove ANSI color codes
            clean_line = ansi_escape.sub('', line)

            match = log_pattern.search(clean_line)
            if match:
                ip = match.group(1)
                path = match.group(3)

                if endpoint in path:
                    total_hits += 1
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # write CSV
    output_file = "endpoint.csv"
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Hits"])

        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

    print(f"\n[+] Total hits on '{endpoint}': {total_hits}")
    print(f"[+] Unique IPs: {len(ip_counts)}")
    print(f"[+] Output saved to {output_file}")


if __name__ == "__main__":
    log_file = input("Enter log file name: ").strip()
    endpoint = input("Enter endpoint (e.g. /cgi-bin): ").strip()

    extract_ips_for_endpoint(log_file, endpoint)
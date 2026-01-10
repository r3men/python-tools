# Log Parser Automation Script by Raymond Zhang
# Note: Script only supports IPV4 currently

import re
import argparse

def classify_ip(ip):
    if ip.startswith("10."):
        return "Private"
    if ip.startswith("192.168."):
        return "Private"
    # 172.16.0.0 – 172.31.255.255
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return "Private"
    return "Public"

# AI-Generated Helper Function for differentiating between public/private IPs

ip_pattern = r"\d+\.\d+\.\d+\.\d+"
# Regex Pattern for standard IP Addresses

ip_storage = {}
suspicious_ips = {}


parser = argparse.ArgumentParser(description="IP Log Analyzer")

parser.add_argument("--file", help="Path to log file")
parser.add_argument("--min", type=int, help="Minimum occurrences to display")
parser.add_argument("--output", help="Output file path")
parser.add_argument("--format", help="Output format: txt/json/csv")

args = parser.parse_args()

# Declare arguments for automation mode

file_path = args.file or input("Enter log file path: ")
if args.min is not None:
    min_threshold = args.min
else:
    threshold_input = input("Enter the minimum number of occurrences to display (or press Enter to use default value of 1): ")
    if threshold_input.strip() == "":
        min_threshold = 1
    else:
        min_threshold = int(threshold_input)

# Ensures a minimum threshold exists, via default/user-input value.

try:
    with open(file_path) as f:
        for line in f:
            ips = re.findall(ip_pattern, line)
            lower_line = line.lower()
            if "failed" in lower_line or "error" in lower_line or "unauthorized" in lower_line or "denied" in lower_line:
                for ip in ips:
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1
            for ip in ips:
                ip_storage[ip] = ip_storage.get(ip, 0) + 1

    sorted_ips = sorted(ip_storage.items(), key=lambda x: x[1], reverse=True)
    # Sort by highest number of occurrences

    for ip, count in sorted_ips:
        if count >= min_threshold:
            ip_type = classify_ip(ip)
            print(ip, f"[{count} Instances] ({ip_type})")
    if args.format:
        save_format = args.format.lower()
    else:
        save_format = input("Save as (txt/json/csv)? Press Enter for default txt: ").strip().lower()
        if save_format == "":
            save_format = "txt"
    valid_formats = ["txt", "json", "csv"]
    if save_format not in valid_formats:
        print("Invalid format. Please choose txt, json, or csv as your output format.")
        exit()
    output_path = args.output or input("Enter output file path (or press Enter to skip): ").strip()
    if output_path:
        try:
            with open(output_path, "w") as out:
                if save_format == "txt":
                    # Save in .txt
                    for ip, count in sorted_ips:
                        if count >= min_threshold:
                            ip_type = classify_ip(ip)
                            out.write(f"{ip} [{count} Instances] ({ip_type})\n")

                elif save_format == "json":
                    # Save in .json
                    import json
                    data = {
                        ip: {
                            "count": count,
                            "type": classify_ip(ip)
                        }
                        for ip, count in sorted_ips
                        if count >= min_threshold
                    }
                    json.dump(data, out, indent=4)

                elif save_format == "csv":
                    # Save in .csv
                    out.write("IP,Count,Type\n")
                    for ip, count in sorted_ips:
                        if count >= min_threshold:
                            ip_type = classify_ip(ip)
                            out.write(f"{ip},{count},{ip_type}\n")
            print(f"Results saved to {output_path}")
        except FileNotFoundError:
            print("Invalid output path. Could not save the file.")
        except PermissionError:
            print("You do not have permission to write to that location.")
    if len(suspicious_ips) > 0:
        print("\nSuspicious activity detected:")
        for ip, count in suspicious_ips.items():
            print(ip, f"[{count} Suspicious Events]")        
    print(f"\nIP addresses found within the log file that match or exceed the minimum threshold have been printed. {len(ip_storage)} unique addresses were found in the file.")
except FileNotFoundError:
    print("File not found")
    exit()
except PermissionError:
    print("You do not have access to read that file.")
    exit()

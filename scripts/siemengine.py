# Basic SIEM Engine by Raymond Zhang

import re
import argparse
from datetime import datetime, timedelta

ip_pattern = r"\d+\.\d+\.\d+\.\d+"
timestamp_pattern = r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"

# Regex Patterns for Detection

parser = argparse.ArgumentParser(description="Basic SIEM Engine by Raymond Zhang")

parser.add_argument("--file", help="Path to the log file")
parser.add_argument("--min", type=int, help="Minimum failure threshold")
parser.add_argument("--spray", type=int, help="Username count threshold for spraying detection")
parser.add_argument("--output", help="Path to save the alert summary (txt)")

args = parser.parse_args()

file_path = args.file or input("Enter the filepath of the input file: ")

try:
    min_threshold = args.min if args.min is not None else int(input("Enter a minimum failure threshold to record: "))
    spray_threshold = args.spray if args.spray is not None else int(input("Enter username count threshold for spraying detection: "))
except ValueError:
    print("ERROR: Thresholds must be integers.")
    exit()

failed_attempts = {}
successful_logins = {}
invalid_users = {}
failed_usernames = {}       
invalid_usernames = {}     
successful_usernames = {}  
failed_timestamps = {}
invalid_timestamps = {}
successful_timestamps = {}

alerts_found = False
static_brute_force_alerts = 0
successful_logins_alerts = 0
static_invalid_user_alerts = 0
spraying_alerts = 0
root_alerts = 0
high_velocity_bruteforce_alerts = 0
slow_bruteforce_alerts = 0
high_velocity_invalid_user_alerts = 0
attack_chain_alerts = 0
login_postenumeration_alerts = 0
spraying_window_alerts = 0

root_alerted = set()
# Count alerts made to authenticate as root user


def alert(message):
    global alerts_found
    if not alerts_found:
        print("\n=== ALERTS ===")
        alerts_found = True
    print(message)

# Detects if an alert is found.

try:
    with open(file_path) as f:
        for line in f:
            ts_match = re.search(timestamp_pattern, line)
            if not ts_match:
                continue
            timestamp_str = ts_match.group(1)
            timestamp = datetime.strptime(timestamp_str + " 2025", "%b %d %H:%M:%S %Y")

            ips = re.findall(ip_pattern, line)
            if not ips:
                continue

            ip = ips[0]
            if "Failed password" in line:
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                failed_timestamps.setdefault(ip, []).append(timestamp)
                match = re.search(r"Failed password for (\w+)", line)
                if match:
                    user = match.group(1)
                    failed_usernames.setdefault(ip, []).append(user)
                    if user == "root" and ip not in root_alerted:
                        alert(f"CRITICAL: {ip} attempted to authenticate as root. High-value target.")
                        root_alerted.add(ip)
                        root_alerts += 1
                
            elif "Invalid user" in line:
                invalid_users[ip] = invalid_users.get(ip, 0) + 1
                invalid_timestamps.setdefault(ip, []).append(timestamp)
                match = re.search(r"Invalid user (\w+)", line)
                if match:
                    user = match.group(1)
                    invalid_usernames.setdefault(ip, []).append(user)
                    if user == "root" and ip not in root_alerted:
                        alert(f"CRITICAL: {ip} attempted to authenticate as root. High-value target.")
                        root_alerted.add(ip)
                        root_alerts += 1
            elif "Accepted password" in line:
                successful_logins[ip] = successful_logins.get(ip, 0) + 1
                successful_timestamps.setdefault(ip, []).append(timestamp)
                match = re.search(r"Accepted password for (\w+)", line)
                if match:
                    user = match.group(1)
                    successful_usernames.setdefault(ip, []).append(user)
                    if user == "root" and ip not in root_alerted:
                        alert(f"CRITICAL: {ip} successfully authenticated as root. Immediate investigation is necessary.")
                        root_alerted.add(ip)
                        root_alerts += 1
except FileNotFoundError:
    print("ERROR: The file path you entered does not exist.")
    exit()
except PermissionError:
    print("ERROR: Permission denied when trying to open the file.")
    exit()

for ip, count in failed_attempts.items():
    if count >= min_threshold and ip in successful_logins:
        alert(f"CRITICAL: {ip} had {count} failed attempts followed by a successful login. Possibly account compromise, successful brute force, or password spraying.")
        successful_logins_alerts += 1
        # Successful Brute Force
    elif count >= min_threshold:
        alert(f"WARNING: {ip} had {count} failed attempts. Possibly a brute force attack.")
        static_brute_force_alerts += 1
        # Brute Force
for ip, count in invalid_users.items():
    if count >= min_threshold:
        alert(f"INFO: {ip} attempted {count} invalid usernames. Possible username enumeration or reconnaissance.")
        static_invalid_user_alerts += 1
        # Username Enumeration / Reconnaissance

for ip, usernames in failed_usernames.items():
    unique_users = set(usernames)
    if len(unique_users) >= spray_threshold:
        max_attempts = max(usernames.count(u) for u in unique_users)
        if max_attempts <= 2:
            alert(f"WARNING: {ip} attempted {len(unique_users)} different usernames with low attempts per user. Possible password spraying attack.")
            spraying_alerts += 1

for ip, times in failed_timestamps.items():
    times.sort()
    for i in range(len(times)):
        window_start = times[i]
        window_end = window_start + timedelta(seconds=60)
        count = sum(time <= window_end for time in times[i:])
        if count >= 5:
            alert(f"CRITICAL: {ip} had {count} failed attempts within 60 seconds.")
            high_velocity_bruteforce_alerts += 1
            break
# Time-Window Rule 1: 5 Failed Attempts within 60s - High Velocity Brute Force

for ip, times in invalid_timestamps.items():
    times.sort()
    for i in range(len(times)):
        window_start = times[i]
        window_end = window_start + timedelta(seconds=30)
        count = sum(time <= window_end for time in times[i:])
        if count >= 10:
            alert(f"INFO: {ip} attempted {count} invalid usernames within 30 seconds.")
            high_velocity_invalid_user_alerts += 1
            break

# Time-Window Rule 2: 10 Invalid Usernames within 30s - High Velocity Invalid User

for ip, times in failed_timestamps.items():
    times.sort()
    for i in range(len(times)):
        window_start = times[i]
        window_end = window_start + timedelta(minutes=10)
        count = sum(time <= window_end for time in times[i:])
        if count >= 20:
            alert(f"WARNING: {ip} had {count} failed attempts within 10 minutes.")
            slow_bruteforce_alerts += 1
            break

# Time-Window Rule 3: 20 Failed Attempts within 10m - Slow Brute Force

for ip, success_times in successful_timestamps.items():
    fail_times = failed_timestamps.get(ip, [])
    invalid_times = invalid_timestamps.get(ip, [])
    if not fail_times or not invalid_times:
        continue
    success_times.sort()
    fail_times.sort()
    invalid_times.sort()
    for success_time in success_times:
        window_start = success_time - timedelta(minutes=2)
        invalid_in_window = any(t >= window_start and t <= success_time for t in invalid_times)
        fails_in_window = any(t >= window_start and t <= success_time for t in fail_times)
        if invalid_in_window and fails_in_window:
            alert(f"CRITICAL: {ip} performed username enumeration, failed attempts, and then successfully logged in within 2 minutes. Full attack chain detected.")
            attack_chain_alerts += 1
            break

# Correlation Rule 1: Reconnaisance --> Failure --> Success within 2m - Attack Chain

for ip, success_times in successful_timestamps.items():
    invalid_times = invalid_timestamps.get(ip, [])
    if not invalid_times:
        continue
    success_times.sort()
    invalid_times.sort()
    for success_time in success_times:
        window_start = success_time - timedelta(minutes=5)
        invalid_in_window = sum(window_start <= t <= success_time for t in invalid_times)
        if invalid_in_window >= 10:
            alert(f"WARNING: {ip} had a successful login within 5 minutes of a username enumeration burst. Possible targeted compromise.")
            login_postenumeration_alerts += 1
            break

# Correlation Rule 2: Successful Login after Enumeration Burst within 5m

for ip, usernames in failed_usernames.items():
    times = failed_timestamps.get(ip, [])
    if not times:
        continue
    times.sort()
    unique_users = set(usernames)
    if len(unique_users) < spray_threshold:
        continue
    for i in range(len(times)):
        window_start = times[i]
        window_end = times[i] + timedelta(minutes=10)
        attempts_in_window = [(times[idx], usernames[idx]) for idx in range(len(times)) if window_start <= times[idx] <= window_end]
        users_in_window = set(user for _, user in attempts_in_window)
        if (len(users_in_window) >= spray_threshold):
            max_attempts_per_user = max(sum(1 for _, u in attempts_in_window if u == user) for user in users_in_window)
            if max_attempts_per_user <= 2:
                alert(f"WARNING: {ip} attempted {len(users_in_window)} usernames within 10 minutes with low attempts per user. Time-window password spraying detected.")
                spraying_window_alerts += 1
                break

# Correlation Rule 3: Time-Window Password Spraying within 10m

if not alerts_found:
    print("No alerts fired.")

total_alerts = (
    static_brute_force_alerts +
    successful_logins_alerts +
    static_invalid_user_alerts +
    spraying_alerts +
    root_alerts +
    high_velocity_bruteforce_alerts +
    high_velocity_invalid_user_alerts +
    slow_bruteforce_alerts +
    attack_chain_alerts +
    login_postenumeration_alerts +
    spraying_window_alerts
)

summary = "\n=== ALERT SUMMARY ===\n"
summary += f"Total Failed Attempts: {sum(failed_attempts.values())}\n"
summary += f"Total Invalid Users: {sum(invalid_users.values())}\n"
summary += f"Total Successful Logins: {sum(successful_logins.values())}\n\n"

summary += "=== STATIC DETECTION RULES ===\n"
summary += f"Static Brute Force Alerts: {static_brute_force_alerts}\n"
summary += f"Fail-to-Success Alerts: {successful_logins_alerts}\n"
summary += f"Static Invalid User Alerts: {static_invalid_user_alerts}\n"
summary += f"Password Spraying Alerts: {spraying_alerts}\n"
summary += f"Root Alerts: {root_alerts}\n\n"

summary += "=== TIME-WINDOW DETECTION RULES ===\n"
summary += f"High-Velocity Brute Force Alerts: {high_velocity_bruteforce_alerts}\n"
summary += f"High-Velocity Invalid User Alerts: {high_velocity_invalid_user_alerts}\n"
summary += f"Slow Brute Force Alerts: {slow_bruteforce_alerts}\n\n"

summary += "=== CORRELATION RULES ===\n"
summary += f"Attack Chain Alerts: {attack_chain_alerts}\n"
summary += f"Successful Login Post Enumeration Alerts: {login_postenumeration_alerts}\n"
summary += f"Time-Window Password Spraying Alerts: {spraying_window_alerts}\n\n"

summary += f"Total Number of Alerts Fired: {total_alerts}\n"

if args.output:
    try:
        with open(args.output, "w") as out:
            out.write(summary)
        print(f"\nSummary written to {args.output}")
    except Exception as e:
        print(f"ERROR: Could not write to output file: {e}")
else:
    print(summary)

# Summary

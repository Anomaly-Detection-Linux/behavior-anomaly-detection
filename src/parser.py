# Log ingestion and parsing subsystem 

"""
This is the parser.py subsystem used for Linux auth.log files.
Looks for these specific event types:
1. Failed Logins 
2. Successful Logins
3. Sudo count usage
"""

import csv
import re


# Patterns for event types 
SUCCESS_PATTERNS = [
    "Accepted password",
    "Accepted publickey",
    "session opened for user"
]

FAILED_PATTERNS = [
    "Failed password",
    "Failed publickey",
    "FAILED LOGIN",
    "authentication failure"
]

SUDO_PATTERNS = [
    "sudo",
    "pam_unix(sudo:session)"
]

# Ignore system users
SYSTEM_USERS = {
    "root", "systemd", "gdm", "gdm-password",
    "daemon", "nobody", "ubuntu"
}

# This function reads the raw log file and returns all lines as a list
def read_logs(file_path: str) -> list[str]:
    # 'errors="ignore"' to prevent the program from crashing in 
    # case malformed characters are encountered. 
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()
    

# This function reads the log file and parses all relevant lines
def parse_logs(file_path: str):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events


# Pattern matcher
def matches_pattern(line: str, patterns: list[str]) -> bool:
    return any(pattern in line for pattern in patterns)


# Extract IP address if possible
def pull_ip(line: str) -> str | None:
    match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
    if match:
        return match.group(1)
    
    match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
    if match:
        return match.group(1)
    
    return None


# Extract user 
def pull_user(line: str) -> str | None:
    #user=xyz
    match = re.search(r"user=([a-zA-Z0-9_-]+)", line)
    if match: 
        return match.group(1)
    
    #for user xyz
    match = re.search(r"for (\w+)", line)
    if match:
        return match.group(1)
    
    #session opened for user xyz
    match = re.search(r"user (\w+)", line)
    if match:
        return match.group(1)
    
    return None
    

# This function reads one log line and structures it by event type
def parse_line(line: str) -> dict | None:
    # Split each line into "pieces" to collect identifiers
    pieces = line.split()

    if len(pieces) < 5:
        return None
    
    # First piece is the timestamp
    timestamp = " ".join(pieces[0:3])

    user = pull_user(line)
    source_ip = pull_ip(line)

    # Ignore system users 
    if(user in SYSTEM_USERS):
        return None


    ### Event 1: Failed login attempt ###
    if matches_pattern(line, FAILED_PATTERNS):
            return{
                "timestamp": timestamp,
                "user": user,
                "event_type": "FAILED_LOGIN",
                "source_ip": source_ip,
                "raw_line": line.strip()
            }
        

    ### Event 2: Successful login attempt ###
    # Only count actual login event and avoid systemd duplicate 
    if matches_pattern(line, SUCCESS_PATTERNS):
            if "cron" in line or "systemd" in line:
                return None

            return{
                "timestamp": timestamp,
                "user": user,
                "event_type": "SUCCESS_LOGIN",
                "source_ip": source_ip,
                "raw_line": line.strip()
            }
        
    
    ### Event 3: Sudo usage ###
    if matches_pattern(line, SUDO_PATTERNS):
        try:
            user = pieces[1]
        except Exception as e:
            print(f"[SUDO parse error] {e} | Line: {line.strip()}")
            user = None

        if user in SYSTEM_USERS:
            return None

        return{
            "timestamp": timestamp,
            "user": user,
            "event_type": "SUDO_COMMAND",
            "source_ip": source_ip,
            "raw_line": line.strip()
        }
    return None


# This function saves all parsed events into a CSV file
def events_to_csv(events: list[dict], output_path: str) -> None:
    fieldnames = ["timestamp", "user", "event_type", "source_ip", "raw_line"]

    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
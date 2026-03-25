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


# Extract timestamp
def pull_timestamp(line: str) -> str | None: 
    #ISO
    match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2})', line)
    if match:
        return match.group(1)
    #syslog
    match = re.match(r'^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})', line)
    if match:
        return match.group(1)
    return None
    

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
    patterns = [
        r"user=([a-zA-Z0-9_-]+)",
        r"session opened for user (\w+)\(uid=",
        r"sudo:\s+(\w+)\s+:",
        r"Accepted (?:password|publickey) for ([a-zA-Z0-9_-]+) from",
        r"Failed (?:password|publickey) for (?:invalid user )?([a-zA-Z0-9_-]+) from",
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    
    return None
    

# This function reads one log line and structures it by event type
def parse_line(line: str) -> dict | None:
    timestamp = pull_timestamp(line)
    if not timestamp:
        return None

    user = pull_user(line)
    source_ip = pull_ip(line)

    event_type = None


    ### Event 1: Failed login attempt ###
    if matches_pattern(line, FAILED_PATTERNS):
        event_type = "FAILED_LOGIN"
    ### Event 2: Successful login attempt ###
    elif matches_pattern(line, SUCCESS_PATTERNS):
        if "cron" in line or "systemd" in line:
            return None
        event_type = "SUCCESS_LOGIN"
    ### Event 3: Sudo usage ###
    elif matches_pattern(line, SUDO_PATTERNS):
        event_type = "SUDO_COMMAND"
    else:
        return None
    
    if not user or user in SYSTEM_USERS:
        return None
    
    return{
        "timestamp": timestamp,
        "user": user,
        "event_type": event_type,
        "source_ip": source_ip,
        "raw_line": line.strip()
    }


# This function saves all parsed events into a CSV file
def events_to_csv(events: list[dict], output_path: str) -> None:
    fieldnames = ["timestamp", "user", "event_type", "source_ip", "raw_line"]

    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
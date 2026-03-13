# Log ingestion and parsing subsystem 

"""
This is the parser.py subsystem used for Linux auth.log files.
Looks for these specific event types:
1. Failed Logins 
2. Successful Logins
3. Sudo count usage
"""

import csv

# System accounts to ignore
SYSTEM_USERS = {"gdm"}

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
    

# This function reads one log line and structures it by event type
def parse_line(line: str) -> dict | None:
    # Split each line into "pieces" to collect identifiers
    pieces = line.split()

    if len(pieces) < 6:
        return None
    
    # First piece is the timestamp
    timestamp = pieces[0]


    ### Event 1: Failed login attempt ###
    if "authentication failure" in line:
        try:
            # Identify the user 
            user = ""

            for piece in pieces:
                if piece.startswith("user="):
                    user = piece.split("=")[1]

            return{
                "timestamp": timestamp,
                "user": user,
                "event_type": "FAILED_LOGIN",
                "source_ip": None,
                "raw_line": line.strip()
            }
        except Exception:
            return None
        

    ### Event 2: Successful login attempt ###
    # Only count actual login event and avoid systemd duplicate 
    if "session opened for user" in line and "gdm-password" in line:
        try:
            # Identify the user first
            user_name = pieces.index("user") + 1
            user = pieces[user_name].split("(")[0]

            if user in SYSTEM_USERS:
                return None


            return{
                "timestamp": timestamp,
                "user": user,
                "event_type": "SUCCESS_LOGIN",
                "source_ip": None,
                "raw_line": line.strip()
            }
        except (ValueError, IndexError):
            return None
        
    
    ### Event 3: Sudo usage ###
    if "sudo" in line:
        try:
            user = pieces[1]

            return{
                "timestamp": timestamp,
                "user": user,
                "event_type": "SUDO_COMMAND",
                "source_ip": None,
                "raw_line": line.strip()
            }
        except (ValueError, IndexError):
            return None
        
    # Ignore the line entirely if it does not match the three event types     
    return None


# This function saves all parsed events into a CSV file
def events_to_csv(events: list[dict], output_path: str) -> None:
    fieldnames = ["timestamp", "user", "event_type", "source_ip", "raw_line"]

    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
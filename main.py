# Main file for integration  

from src.parser import parse_logs, events_to_csv

# Main execution function 
def main():
    print("SP-110-TESTING")

    # Define the filepath for the parser to access authentication logs
    input_path = "data/raw/auth.log"
    # Define output filepath for parsed events
    output_path = "data/processed/events.csv"

    # Parse the log file into structured events 
    events = parse_logs(input_path)

    # Print statement for confirmation 
    print(f"Parsed {len(events)} events from {input_path}")

    # Verify the first few parsed events 
    print("\nVerifying first 5 lines: ")
    for event in events[:5]:
        print(event)

    # Save parsed events to CSV
    events_to_csv(events, output_path)
    print(f"Saved parsed events to {output_path}")



if __name__ == "__main__":
    main()

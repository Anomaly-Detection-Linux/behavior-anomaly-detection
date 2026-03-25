# Main file for integration  

from src.parser import parse_logs, events_to_csv
from src.features import extract_features
from src.model import run_model
from src.alerts import generate_alerts
from pathlib import Path
import sys

# Main execution function 
def main():
    print("SP-110-TESTING")

    # Define the filepaths 
    input_path = "data/custom_auth.log"                 #raw log file
    events_output = "data/processed/events.csv"         #parsed events
    features_output = "data/processed/features.csv"     #extracted features 
    anomalies_output = "data/processed/anomalies.csv"   #model output 
    alerts_csv = "data/processed/alerts.csv"            #alert csv file
    report_file = "data/output/anomaly_report.txt"      #human-readable report 


    # Parse the log file into structured events 
    try:
        events = parse_logs(input_path)
        print(f"Parsed {len(events)} events from {input_path}")

        # Verify the first few parsed events 
        print("\nVerifying first 3 lines: ")
        for event in events[:3]:
            print(event)
    
        # Save parsed events to CSV
        events_to_csv(events, events_output)
        print(f"Saved parsed events to {events_output}")
    except Exception as e:
        print(f"Error during log parsing: {e}")
        sys.exit(1)



    # Run feature extraction
    try:
        extract_features(events_output, features_output)
        print(f"Saved relevant features to {features_output}")
    except Exception as e:
        print(f"Error during feature extraction: {e}")
        sys.exit(1)



    # Run anomaly detection model 
    try:
        anomalies_df = run_model(features_output, events_output)
        anomalies_df.to_csv(anomalies_output, index=False)
        print(f"Anomaly detection complete. Saved anomalies to {anomalies_output}")
    except Exception as e:
        print(f"Error during anomaly detection: {e}")
        sys.exit(1)



    # Generate alert output 
    try:
        generate_alerts(anomalies_output, alerts_csv, report_file, top_n=5)
    except Exception as e:
        print(f"Error during alert generation: {e}")
        sys.exit(1)
    


if __name__ == "__main__":
    Path("data/processed").mkdir(parents=True, exist_ok=True)
    Path("data/output").mkdir(parents=True, exist_ok=True)
    main()

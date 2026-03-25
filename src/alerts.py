# Alert generator subsystem 

import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt

# Reads the models output file and generates alerts for anomalies with reason indicators
# and other necessary information 
def  generate_alerts(anomalies_file, alerts_csv, report_file, top_n = 5):
    df = pd.read_csv(anomalies_file)

    df.to_csv(alerts_csv, index=False)

    # Generate a summary 
    total_anomalies = len(df)
    anomalies_per_user = df['user'].value_counts()
    anomalies_by_type = df['event_type'].value_counts()


    #Print summary to command line 
    print(f"Behavioral Anomaly Summary\n")
    print(f"--------------------------\n\n")
    print(f"Total anomalies detected: {total_anomalies}\n\n")

    print(f"Anomalies by user: \n")
    for user, count in anomalies_per_user.items():
        print(f"  {user}: {count}\n")
    print("Anomalies by event type: \n")
    for etype, count in anomalies_by_type.items():
        print(f" {etype}: {count}\n")


    # Print first few anomalies to command line 
    print(f"\nFirst {top_n} anomalies (timestamp | user | event_type | score): ")
    for _, row in df.head(top_n).iterrows():
        print(f"{row['timestamp']} | {row['user']} | {row['event_type']} | score: {row['anomaly_score']:.2f}")
        print(f"Raw log: {row['raw_line']}\n")

    # Create human-readable report 
    report_path = Path(report_file)
    with open(report_path, "w") as f:
        f.write(f"Behavioral Anomaly Report\n")
        f.write(f"--------------------------\n\n")
        f.write(f"Total anomalies detected: {total_anomalies}\n\n")

        f.write(f"Anomalies by user: \n")
        for user, count in anomalies_per_user.items():
            f.write(f"  {user}: {count}\n")
        f.write("Anomalies by event type: \n")
        for etype, count in anomalies_by_type.items():
            f.write(f" {etype}: {count}\n")

        f.write("\nDescription of Anomalies: \n")
        for _, row in df.iterrows():
            f.write(f"Timestamp: {row['timestamp']} | User: {row['user']} | "
                    f"Event Type: {row['event_type']} | Anomaly Score: {row['anomaly_score']:.2f}\n"
            )
            f.write(f"  Raw log: {row['raw_line']}\n\n")


    # Create plots for anomalies 
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    for col in ['login_attempts', 'failed_logins', 'sudo_usage']:
        if col in df.columns:
            plt.figure(figsize=(10,4))
            plt.plot(df['timestamp'], df[col], label=col)
            plt.scatter(df['timestamp'], df[col], c='red', label='Anomaly')
            plt.xlabel('Time')
            plt.ylabel(col)
            plt.title(f'{col} over time with anomalies')
            plt.legend()
            plt.tight_layout()
            plt.savefig(f"data/output/{col}_anomalies.png")
            plt.close()
    
    print(f"Alerts saved to {alerts_csv} and full report saved to {report_path}")
    print("Plots saved to data/output/")


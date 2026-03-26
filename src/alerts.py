# Alert generator subsystem 

import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# Reads the models output file and generates alerts for anomalies with reason indicators
# and other necessary information 
def  generate_alerts(anomalies_file, alerts_csv, report_file, top_n = 5):
    df = pd.read_csv(anomalies_file)

    if "anomaly_label" in df.columns:
        df = df[df["anomaly_label"] == -1].copy()


    alert_columns = [
        "timestamp",
        "user",
        "event_type",
        "source_ip",
        "anomaly_score",
        "severity",
        "anomaly_reason",
    ]
    df[alert_columns].to_csv(alerts_csv, index=False)


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
        print(f"{row['timestamp']} | {row['user']} | {row['event_type']}")
        print(f"Score: {row['anomaly_score']:.2f} | Severity: {row['severity']}")
        print(f"Reason: {row['anomaly_reason']}")
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
            f.write(
            f"Timestamp: {row['timestamp']} | User: {row['user']} | "
            f"Event Type: {row['event_type']} | "
            f"Anomaly Score: {row['anomaly_score']:.2f} | "
            f"Severity: {row['severity']}\n"
            )
            f.write(f"Reason: {row['anomaly_reason']}\n")
            f.write(f"  Raw log: {row['raw_line']}\n\n")


    # Create plots for anomalies 
    plot_df = df.groupby(["user", "hour_window"], as_index=False).agg({
        "failed_logins": "max",
        "sudo_usage": "max",
        "login_attempts": "max"
    })
    plot_df["hour_window"] = pd.to_datetime(plot_df["hour_window"], utc=True)
    plot_df = plot_df.sort_values(by="hour_window")


    for col in ["login_attempts", "failed_logins", "sudo_usage"]:
        if col in plot_df.columns:
            plt.figure(figsize=(10,4))

            for user in plot_df["user"].unique():
                user_df = plot_df[plot_df["user"] == user].sort_values("hour_window")
                plt.scatter(user_df["hour_window"], user_df[col], label=user)

            plt.xlabel('Time')
            plt.ylabel(col)
            plt.title(f"{col} anomalies by user")
            plt.legend()
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig(f"data/output/{col}_anomalies.png")
            plt.close()
    
    print(f"Alerts saved to {alerts_csv} and full report saved to {report_path}")
    print("Plots saved to data/output/")


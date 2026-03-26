# Isolation Forest modeling subsystem 

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Trains the isolation forest using auto contamination and returns a dataframe with 
# anomaly scores and binary classification lables 
def run_model(input_file: str, events_file: str) -> pd.DataFrame:
    features_df = pd.read_csv(input_file)
    features_df["hour_window"] = pd.to_datetime(features_df["hour_window"])
    
    # Select features from file to be evaluated 
    columns = [
        "failed_logins", 
        "sudo_usage", 
        "unique_source_ip",
        "failed_ratio", 
        "hour_of_day"
    ]

    # Scale features for better anomaly detection 
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(features_df[columns])

    # Train the model 
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(scaled_data)

    # Predictions and anomaly scores
    features_df["anomaly_label"] = clf.predict(scaled_data) #-1 = anomaly, 1 = normal
    features_df["anomaly_score"] = clf.decision_function(scaled_data) * -1 
    features_df["anomaly_reason"] = features_df.apply(get_anomaly_reason, axis=1)
    features_df["severity"] = features_df.apply(get_severity_level, axis=1)

    events_df = pd.read_csv(events_file)
    events_df["hour_window"] = pd.to_datetime(events_df["hour_window"])

    # Merge events for alerts
    merge_df = pd.merge(
        events_df,
        features_df,
        on=["user", "hour_window"],
        how="left",
        suffixes=("", "_feature")
    )

    # Filter by anomalies 
    anomalies_only = merge_df[merge_df["anomaly_label"] == -1].copy()

    # Sort so strongest anomalies show up first 
    anomalies_only = anomalies_only.sort_values(
        by="anomaly_score",
        ascending=False
    )

    return anomalies_only

# Create reasons per detected anomaly for alert output 
def get_anomaly_reason(row):
    reasons = []

    if row["failed_logins"] >= 5:
        reasons.append("High failed login count")
    if row["failed_ratio"] >= 0.8:
        reasons.append("High failed login ratio")
    if row["sudo_usage"] >= 3:
        reasons.append("Excessive sudo usage")
    if row["hour_of_day"] < 5:
        reasons.append("Multiple source IPs")
    if row["unique_source_ip"] > 1:
        reasons.append("Multiple source IPs")

    if not reasons:
        return "General anomaly detected"
    
    return "; ".join(reasons)


# Calculate anomaly severity level
def get_severity_level(row):
    reason_count = 0

    if row["failed_logins"] >= 5:
        reason_count += 1
    if row["failed_ratio"] >= 0.8:
        reason_count += 1
    if row["sudo_usage"] >= 3:
        reason_count += 1
    if row["hour_of_day"] < 5:
        reason_count += 1
    if row["unique_source_ip"] > 1:
        reason_count += 1
    
    if row["anomaly_score"] >= 0.15 or reason_count >= 4:
        return "HIGH"
    elif row["anomaly_score"] >= 0.05 or reason_count >= 2:
        return "MEDIUM"
    else:
        return "LOW"
    
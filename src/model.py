# Isolation Forest modeling subsystem 

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Trains the isolation forest using auto contamination and returns a dataframe with 
# anomaly scores and binary classification lables 
def run_model(input_file: str, events_file: str) -> pd.DataFrame:
    features_df = pd.read_csv(input_file)
    
    # Select features from file to be evaluated 
    columns = [
        "successful_logins", 
        "failed_logins", 
        "sudo_usage", 
        "unique_source_ip",
        "login_attempts", 
        "failed_ratio", 
        "hour_of_day"
    ]

    # Scale features for better anomaly detection 
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(features_df[columns].to_numpy())

    # Train the model 
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(scaled_data)

    # Predictions and anomaly scores
    features_df["anomaly_label"] = clf.predict(scaled_data) #-1 = anomaly, 1 = normal
    features_df["anomaly_score"] = clf.decision_function(scaled_data) * -1 

    events_df = pd.read_csv(events_file)

    # Merge events for alerts
    merge_df = pd.merge(
        events_df,
        features_df,
        on=['user', 'hour_window'],
        how='left',
        suffixes=("", "_feature")
    )

    return merge_df

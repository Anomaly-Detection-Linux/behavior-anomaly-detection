# Feature Extraction subsystem
import pandas as pd # type: ignore

def extract_features(input_file, output_file):

    df = pd.read_csv(input_file)

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    df["hour_window"] = df["timestamp"].dt.floor("H")

    # Calculate behavioral features
    features = df.groupby(["user", "hour_window"]).agg(
        login_attempts=("event_type", lambda x: (x == "login").sum()),
        failed_logins=("event_type", lambda x: (x == "failed_login").sum()),
        sudo_usage=("event_type", lambda x: (x == "sudo").sum())
    ).reset_index()

    features.to_csv(output_file, index=False)

    print("Feature extraction completed.")
    print(features)


if __name__ == "__main__":

    input_file = "events.csv"
    output_file = "features.csv"

    extract_features(input_file, output_file)

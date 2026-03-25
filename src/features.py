# Feature Extraction subsystem
import pandas as pd # type: ignore

def extract_features(input_file, output_file):

    df = pd.read_csv(input_file)

    # Convert timestamp 
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Round down to nearest hour
    df["hour_window"] = df["timestamp"].dt.floor("H")

    # Calculate behavioral features
    features = df.groupby(["user", "hour_window"]).agg(
        login_attempts=("event_type", lambda x: (x == "SUCCESS_LOGIN").sum()),
        failed_logins=("event_type", lambda x: (x == "FAILED_LOGIN").sum()),
        sudo_usage=("event_type", lambda x: (x == "SUDO_COMMAND").sum())
    ).reset_index()

    features.to_csv(output_file, index=False)

    print("Feature extraction completed.")
    print(features)


if __name__ == "__main__":

    input_file = "events.csv"
    output_file = "features.csv"

    extract_features(input_file, output_file)

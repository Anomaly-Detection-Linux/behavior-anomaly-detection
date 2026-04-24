# SP-110 Red Linux
**Behavior-Based Anomaly Detection in Linux User Activity Logs**

## Course Information
- Course: CS 4850 Section 02  
- Semester: Spring 2026  

## Team Members
- Emma Dietz – Team Lead, Development & Documentation  
- Luke McLendon – Documentation & Testing  
- Chaathurya Nakkana – Development & Documentation  
- Noor Aftab – Documentation & Testing  

## Project Overview
This project focuses on behavior-based anomaly detection in Linux user activity and authentication logs.  
The system uses machine learning techniques (Isolation Forest) to identify unusual or suspicious behavior.

## Project Links
- **Website:** https://anomaly-detection-linux.github.io/  
- **Website Repository:** https://github.com/Anomaly-Detection-Linux/anomaly-detection-linux.github.io 
- **Final Report (PDF):** [add pdf link]  
- **Final Presentation Video:**   [add video link]

## Technologies Used
- Python  
- NumPy  
- Pandas  
- scikit-learn  
- Matplotlib  
- Linux (Ubuntu)  
- VirtualBox

## How the System Works 

The system follows a pipeline-based architecture:

1. **Log Ingestion & Parsing**  
   Reads Linux authentication logs and extracts structured events.

2. **Feature Extraction**  
   Groups events into hourly windows and generates behavioral features such as:
   - Login attempts  
   - Failed logins  
   - Sudo usage  

3. **Anomaly Detection (Isolation Forest)**  
   Applies an unsupervised model to identify deviations from normal behavior.

4. **Alert Generation**  
   Produces:
   - `alerts.csv` (structured anomaly output)  
   - Text report
   - Graph visualizations  

---

## How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/Anomaly-Detection-Linux/behavior-anomaly-detection
cd SP-110-Red-Linux
```
### 2. Install Dependencies 
- Make sure you are using Python 3.
```bash
pip install -r requirements.txt
```
- If needed (Ubuntu):
```bash
sudo apt install python3-pip
```

### 3. Run the Program

```bash
python3 main.py data/raw/auth.log
```
```md
> You can replace `data/raw/auth.log` with any valid Linux authentication log file.
```

---

## Output 
After running the program, the system generates:

- alerts.csv (detected anomalies)
- report.txt (summary of results)
- Graphs showing anomaly trends

All outputs are saved in:
```bash
data/output/
```

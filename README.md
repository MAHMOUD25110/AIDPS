# Intrusion Detection and Prevention System (IDPS)

A real-time network intrusion detection and prevention project built with Python. It captures live packets, extracts KDD-style features, classifies traffic with a pre-trained model, blocks suspicious IPs at the OS firewall layer, and exposes a live Flask dashboard for monitoring alerts and blocked hosts.

## Key Features

- Real-time packet capture using `scapy`
- Packet-to-feature extraction approximating KDD intrusion detection characteristics
- Pre-trained model inference using saved artifacts in `Models/`
- Automatic IP blocking using Windows Firewall or Linux `iptables`
- Event logging and block management via SQLite
- Flask dashboard with live alerts, blocked IP list, and timeline charts

## Repository Structure

- `src/`
  - `config.py` - project path configuration and constants
  - `Database/database.py` - SQLite logging, alert retrieval, blocked-IP management
  - `Routes/app.py` - Flask application serving the dashboard and API endpoints
  - `Routes/templates/dashboard.html` - dashboard UI template
  - `Routes/static/js/main.js` - frontend logic fetching API data and updating charts/tables
  - `Scripts/features.py` - packet feature extraction and preprocessing pipeline
  - `Scripts/model_loader.py` - loads saved model, scaler, and expected one-hot columns
  - `Scripts/realtime_pipeline.py` - main IDS pipeline that sniff packets, classify them, and block malicious IPs
  - `Scripts/firewall.py` - OS-aware IP blocking/unblocking implementation
- `Models/`
  - trained model artifacts, scaler, and one-hot encoding metadata
- `archive/`
  - `KDDTrain+.txt`, `KDDTest+.txt` - source dataset files used for training and evaluation
- `NOTEBOOKS/`
  - Jupyter notebook for model analysis and experimentation
- `requirements.txt` - Python dependencies for the project

## Requirements

- Python 3.11+
- Administrator/root privileges for packet sniffing and firewall operations
- Recommended to use a virtual environment or Conda environment

## Setup

1. Create or activate a Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3. Confirm the following model artifacts exist in `Models/`:

- `rf_model.pkl`
- `scaler.pkl`
- `onehot_columns.pkl`

These are required by `src/Scripts/realtime_pipeline.py`.

## Running the System

### 1. Start the Flask dashboard

```powershell
python src\Routes\app.py
```

Open your browser to `http://localhost:5000` to view the live monitoring dashboard.

### 2. Start the real-time IDS pipeline

```powershell
python src\Scripts\realtime_pipeline.py
```

This process captures live packets, classifies them, logs alerts, and blocks suspicious source IPs.

> Note: The IDS pipeline and dashboard run independently. For complete monitoring, run both concurrently.

## How It Works

1. `src/Scripts/realtime_pipeline.py` initializes the SQLite database and loads the saved model artifacts.
2. Live packets are captured using `scapy.sniff()`.
3. `src/Scripts/features.py` extracts a feature dictionary from each packet and preprocesses it to match the model input.
4. The loaded model predicts whether the packet is malicious.
5. On a malicious detection, the source IP is blocked using `src/Scripts/firewall.py` and logged to the database.
6. `src/Routes/app.py` exposes API endpoints that power the dashboard UI with alert history, blocked IPs, and stats.

## Dashboard Capabilities

- Total alerts count
- Active blocked IP count
- Top protocol seen in alerts
- Alerts timeline chart
- Recent alerts table
- Blocked IPs table with manual unblock support

## Notes and Limitations

- The feature extraction is an approximation and does not fully replicate a full KDD connection-state pipeline.
- Firewall blocking requires elevated privileges and may behave differently between Windows and Linux.
- The dashboard polls every 5 seconds, so it reflects recent database state rather than instant packet-by-packet updates.

## Additional Resources

- `NOTEBOOKS/intrusion-detection-system-with-ml-dl.ipynb` contains exploratory analysis and model development notes.
- `archive/KDDTrain+.txt` and `archive/KDDTest+.txt` are the KDD dataset files used for training and testing.

## Troubleshooting

- If the pipeline fails to start, verify the model artifacts exist and the Python environment has `scapy`, `flask`, `joblib`, and `pandas` installed.
- On Windows, run PowerShell as Administrator before starting the pipeline or dashboard.
- If blocking fails, check that firewall commands are permitted on your host.

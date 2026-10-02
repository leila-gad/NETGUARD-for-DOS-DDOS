# NETGUARD — ML-Based DoS/DDoS Detection

NETGUARD is a machine learning system for real-time detection of **Denial-of-Service (DoS)** and **Distributed Denial-of-Service (DDoS)** attacks on network traffic.

Built using the **CICIDS2017 dataset**, the system classifies network flows as **BENIGN** or **ATTACK** using an XGBoost model, achieving **99.98% accuracy** on the test set.

The trained model is exposed through a **Flask REST API** and deployed using **Docker**.

---

## 1. What is a DoS Attack?

A **DoS (Denial-of-Service)** attack is an attempt by a single attacker to make a server or network resource unavailable.

The attacker sends a large number of requests or packets, consuming resources such as bandwidth, CPU, memory, or connection capacity.

### Normal Traffic

```text
User A ──────────> Server
        legitimate request

User B ──────────> Server
        legitimate request

Server responds normally
```

### DoS Attack

```text
Attacker ───────────────────────────────> Server
          large number of fake requests

Server becomes overloaded
        → slow or unavailable
```

### DoS Attack Types Used in This Project

The Wednesday CICIDS2017 dataset contains several DoS attack types:

| Attack               | Description                                                                   |
| -------------------- | ----------------------------------------------------------------------------- |
| **DoS Hulk**         | Floods a web server with a large number of HTTP requests.                     |
| **DoS GoldenEye**    | Keeps HTTP connections open using specially crafted requests.                 |
| **DoS Slowloris**    | Opens many connections and keeps them incomplete to exhaust server resources. |
| **DoS Slowhttptest** | Sends HTTP requests very slowly to keep server resources occupied.            |
| **Heartbleed**       | Exploits a vulnerability in OpenSSL to access data from server memory.        |

---

## 2. What is a DDoS Attack?

A **DDoS (Distributed Denial-of-Service)** attack follows the same basic idea as a DoS attack, but the traffic comes from **many compromised machines at the same time**.

These machines are often part of a **botnet**, making the attack more difficult to block because the traffic comes from many different sources.

### Normal DoS

```text
1 attacker ──────────> Server
```

### DDoS

```text
Botnet 1 ──┐
Botnet 2 ──┤
Botnet 3 ──┼────────> Server
Botnet 4 ──┤
...         ┘
```

### DDoS Attack Used in This Project

The Friday CICIDS2017 dataset contains **DDoS traffic**, including large-scale UDP/TCP flooding traffic designed to overwhelm the target.

---

## 3. How Does Machine Learning Detect These Attacks?

DoS and DDoS attacks create network traffic patterns that can be statistically different from normal traffic.

For example, an attack can produce:

* Very high packet rates
* Very short or unusual flow durations
* Repeated packet sizes
* Abnormal TCP flag patterns
* Very small inter-arrival times
* Large numbers of connections

### Example: Normal Traffic

```text
Flow Duration     = longer
Packets/s         = relatively low
SYN Flag Count    = normal connection behavior
IAT               = irregular
Active/Idle       = alternating
```

### Example: DoS Traffic

```text
Flow Duration     = often very short
Packets/s         = very high
SYN Flag Count    = potentially high
IAT               = often very regular
Active/Idle       = highly active
```

### Example: DDoS UDP Flood

```text
Protocol          = UDP
Packet Size       = often similar
Packet Variation  = low
TCP Flags         = not applicable
Packet Rate       = very high
```

These statistical patterns are used by **XGBoost** to distinguish between BENIGN and ATTACK traffic.

---

## 4. Dataset — CICIDS2017

The **CICIDS2017** dataset was created by the **Canadian Institute for Cybersecurity at the University of New Brunswick**.

It contains normal and malicious network traffic collected over several days. The traffic was captured and converted into network-flow features using **CICFlowMeter**.

A **network flow** represents packets exchanged between network endpoints and contains statistical information about the communication.

Instead of analyzing raw packet data, CICFlowMeter calculates features such as:

* Packet sizes
* Flow duration
* Packet rates
* Inter-arrival times
* TCP flags
* Active/idle times
* Forward and backward traffic statistics

### Dataset Files Used

| File                                               | Day       | Traffic      | Approx. Rows |
| -------------------------------------------------- | --------- | ------------ | -----------: |
| `Monday-WorkingHours.pcap_ISCX.csv`                | Monday    | BENIGN       |     ~529,918 |
| `Wednesday-WorkingHours.pcap_ISCX.csv`             | Wednesday | DoS attacks  |     ~692,703 |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Friday    | DDoS attacks |     ~225,745 |

Each day represents a different traffic scenario. Keeping the datasets separate makes it easier to study each scenario independently.

### Feature Categories

The original dataset contains **83 features**, reduced to **68 features** after preprocessing.

| Category               | Examples                                    | Purpose                             |
| ---------------------- | ------------------------------------------- | ----------------------------------- |
| **Flow Timing**        | Flow Duration, Flow Packets/s, Flow Bytes/s | Measures traffic rate and duration  |
| **Packet Length**      | Mean, Std, Min, Max                         | Describes packet size patterns      |
| **Inter-Arrival Time** | Flow IAT Mean, IAT Std                      | Measures time between packets       |
| **TCP Flags**          | SYN, ACK, FIN, RST, PSH                     | Describes connection behavior       |
| **Window Size**        | Initial forward/backward window             | Describes TCP connection properties |
| **Active/Idle Time**   | Active Mean, Idle Mean                      | Describes traffic activity          |
| **Subflows**           | Forward/Backward Packets and Bytes          | Describes flow segments             |

---

## 5. Data Processing Pipeline

Raw CICIDS2017 CSV files cannot be directly used by the model.

The preprocessing pipeline performs several steps to clean and prepare the data.

```text
Friday DDoS CSV ──────┐
Wednesday DoS CSV ────┼──> Merge
Monday Normal CSV ────┘
                       │
                       ▼
              Clean column names
                       │
              Remove duplicates
                       │
          Remove zero-variance features
                       │
             Replace Inf → NaN
                       │
             Fill NaN with median
                       │
              Encode labels
              BENIGN = 0
              ATTACK = 1
                       │
                       ▼
              Stratified Split
                ┌──────┴──────┐
                │             │
             80% Train     20% Test
             1,158,692      289,674
                │             │
                ▼             │
          Fit MinMaxScaler    │
                │             │
                ▼             │
         Transform Train      │
         and Test data        │
                │             │
                ▼             │
           Train XGBoost      │
                │             │
                └──────┬──────┘
                       ▼
                  Evaluate Model
                       │
                       ▼
              Save Model Artifacts
```

The test set is kept separate during training so that the model can be evaluated on data it has not seen during training.

---

## 6. Model Training

NETGUARD uses **XGBoost**, a gradient-boosting algorithm based on decision trees.

The model builds multiple trees sequentially, with each new tree helping correct errors made by previous trees.

XGBoost was selected because it:

* Works well with structured/tabular data
* Handles large datasets efficiently
* Provides probability predictions
* Performs well for classification tasks

---

## 7. Results

The model was evaluated on **289,674 test samples**.

| Metric    |       Score |
| --------- | ----------: |
| Accuracy  |  **99.98%** |
| Precision |  **99.94%** |
| Recall    |  **99.98%** |
| F1-Score  |  **99.96%** |
| ROC-AUC   | **100.00%** |

> High performance on CICIDS2017 is partly explained by the strong statistical differences between normal and attack traffic. The project therefore focuses not only on model training, but also on data preprocessing, API integration, real-time inference, and deployment.

---

## 8. Flask REST API

The trained model is exposed through a REST API built with **Flask**.

The application can be served with **Gunicorn** for deployment.

| Method | Endpoint         | Description                       |
| ------ | ---------------- | --------------------------------- |
| `GET`  | `/`              | Serves the frontend dashboard     |
| `GET`  | `/health`        | Returns API and model status      |
| `POST` | `/predict`       | Classifies a single network flow  |
| `POST` | `/predict/batch` | Classifies multiple network flows |
| `GET`  | `/logs`          | Returns prediction logs           |
| `GET`  | `/features`      | Returns the model features        |

### Prediction Flow

```text
Network Flow
     │
     ▼
Flask API
     │
     ▼
Data Preparation
     │
     ▼
MinMaxScaler
     │
     ▼
XGBoost Model
     │
     ▼
Prediction
     │
     ├── BENIGN
     │
     └── ATTACK
```

---

## 9. Frontend Dashboard

NETGUARD includes a web dashboard built with **HTML, CSS, JavaScript, and Chart.js**.

The dashboard provides:

* API connection status
* Total analyzed flows
* Number of detected attacks
* Number of benign flows
* Attack rate
* Network flow input
* DoS and benign simulation buttons
* ATTACK/BENIGN prediction
* Confidence and risk level
* Confidence progress bar
* Live traffic chart
* Timestamped prediction logs

### Dashboard Architecture

```text
Browser
   │
   ▼
Frontend
HTML / CSS / JavaScript
   │
   │ POST /predict
   ▼
Flask REST API
   │
   ▼
XGBoost Model
   │
   ▼
Prediction
   │
   ▼
Dashboard
```

---

## 10. Docker Containerization

The application is containerized with **Docker** to make deployment more portable and reproducible.

| File                 | Purpose                                   |
| -------------------- | ----------------------------------------- |
| `Dockerfile`         | Builds the application image              |
| `docker-compose.yml` | Runs and manages the container            |
| `.dockerignore`      | Excludes unnecessary files from the image |
| `requirements.txt`   | Defines Python dependencies               |

The container runs the Flask application using **Gunicorn**.

---

## 11. Project Structure

```text
NETGUARD-for-DOS-DDOS/
│
├── backend/
│   └── app.py
│
├── frontend/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       └── js/
│
├── src/
│   ├── preprocess.py
│   └── model_training.py
│
├── data/
│   ├── raw/
│   └── processed/
│
├── models/
│   ├── dos_detector.pkl
│   ├── scaler.pkl
│   └── feature_names.pkl
│
├── results/
│   ├── metrics.txt
│   └── confusion_matrix.png
│
├── logs/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 12. Tech Stack

| Component            | Technologies                    |
| -------------------- | ------------------------------- |
| **Machine Learning** | XGBoost, scikit-learn           |
| **Data Processing**  | Pandas, NumPy                   |
| **Backend / API**    | Flask, Flask-CORS, Gunicorn     |
| **Frontend**         | HTML, CSS, JavaScript, Chart.js |
| **Containerization** | Docker, Docker Compose          |
| **Dataset**          | CICIDS2017                      |
| **Language**         | Python 3.11                     |

---

## 13. Key Features

* Machine learning-based DoS/DDoS detection
* Binary classification: BENIGN / ATTACK
* XGBoost model
* 68 network-flow features
* Flask REST API
* Single-flow and batch prediction
* Real-time dashboard
* Prediction logging
* Dockerized deployment
* Reproducible preprocessing and model artifacts

## 11. Getting Started — From Clone to Deployment

This section explains how to clone NETGUARD, prepare the environment, run the application locally, and deploy it with Docker.

### 11.1 Clone the Repository

Clone the GitHub repository:

```bash
git clone https://github.com/leila-gad/NETGUARD-for-DOS-DDOS.git
cd NETGUARD-for-DOS-DDOS
```

### 11.2 Create a Python Virtual Environment

NETGUARD uses Python 3.11.

On Windows:

```powershell
py -3.11 -m venv .venv
```

Activate the virtual environment:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

You should see:

```text
(.venv)
```

at the beginning of your terminal.

### 11.3 Install Dependencies

The Python dependencies are located in the `deployment/` directory.

Install them with:

```powershell
pip install -r .\deployment\requirements.txt
```

### 11.4 Verify the Model Files

The trained model and preprocessing artifacts must be available in:

```text
models/
├── dos_detector.pkl
├── scaler.pkl
└── feature_names.pkl
```

These files are required by the Flask API.

If the model artifacts are not included in the repository, run the preprocessing and training scripts first:

```powershell
python src/preprocess.py
python src/model_training.py
```

This generates the required model artifacts inside `models/`.

### 11.5 Run the Flask API Locally

Start the application from the project root:

```powershell
python .\backend\app.py
```

The API should be available at:

```text
http://localhost:5000
```

Open the URL in a browser to access the NETGUARD dashboard.

You can also test the health endpoint:

```text
http://localhost:5000/health
```

### 11.6 Build the Docker Image

NETGUARD can be packaged into a Docker image for reproducible deployment.

The Docker configuration is located in:

```text
deployment/
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

From the project root, build the image with:

```powershell
docker compose -f .\deployment\docker-compose.yml build
```

This performs the following steps:

```text
Dockerfile
    ↓
Install Python 3.11
    ↓
Install dependencies
    ↓
Copy Flask backend
    ↓
Copy frontend
    ↓
Copy trained model
    ↓
Create Docker image
```

Verify that the image was created:

```powershell
docker images
```

You should see:

```text
dos-detector    latest
```

### 11.7 Start the Docker Container

Start the application in detached mode:

```powershell
docker compose -f .\deployment\docker-compose.yml up -d
```

Check that the container is running:

```powershell
docker ps
```

The container should appear with the name:

```text
dos-detector-api
```

The application is exposed on port `5000`:

```text
http://localhost:5000
```

### 11.8 Test the Deployment

Open the dashboard:

```text
http://localhost:5000
```

Test the API health endpoint:

```text
http://localhost:5000/health
```

You can also check the container logs:

```powershell
docker logs dos-detector-api
```

### 11.9 Stop the Application

To stop the container:

```powershell
docker compose -f .\deployment\docker-compose.yml down
```

To start it again:

```powershell
docker compose -f .\deployment\docker-compose.yml up -d
```

Prediction logs are stored using the Docker volume:

```text
logs_data
```

This allows logs to persist across container restarts.

### 11.10 Complete Deployment Flow

The complete workflow is:

```text
Clone Repository
       │
       ▼
Create Python Environment
       │
       ▼
Install Dependencies
       │
       ▼
Prepare / Train Model
       │
       ▼
Model Artifacts
       │
       ▼
Run Flask API
       │
       ▼
Test Locally
       │
       ▼
Docker Compose Build
       │
       ▼
Docker Image
       │
       ▼
Docker Compose Up
       │
       ▼
Running Container
       │
       ▼
http://localhost:5000
       │
       ▼
NETGUARD Dashboard
```


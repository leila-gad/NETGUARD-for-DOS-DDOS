NETGUARD is a machine learning system for real-time detection of Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks on network traffic. Built on the CICIDS2017 dataset, the system classifies network flows as BENIGN or ATTACK with 99.98% accuracy and exposes predictions through a production-ready Flask REST API served inside a Docker container.

# 1/ What is DoS attacks?
DoS attack is an attempt by a single attacker machine to make a server or network resource unavailable by flooding it with illegitimate requests — exhausting its bandwidth, CPU, or memory until it can no longer serve real users.

Normal traffic:
  User A ──► Server  (legitimate request)
  User B ──► Server  (legitimate request)
  Server responds normally ✓

DoS attack:
  Attacker ──────────────────────────────────────────► Server
             millions of fake requests per second
             Server overwhelmed → crashes or stops responding ✗

Common DoS attack types used in this project (Wednesday CICIDS2017):
| DoS Hulk | Floods the web server with unique HTTP GET requests — bypasses caching |
| DoS GoldenEye | Keeps HTTP connections open indefinitely using random headers |
| DoS Slowloris | Opens many partial HTTP connections and never completes them — exhausts connection pool |
| DoS Slowhttptest | Sends HTTP requests very slowly, keeping server threads busy waiting |
| Heartbleed | Exploits OpenSSL vulnerability — leaks server memory via malformed heartbeat packets |

# 2/ What is DDoS attacks:
DDoS attack is the same concept but launched from thousands of compromised machines simultaneously (a botnet). This makes it far harder to block — traffic comes from many different IPs.

Normal DoS:
  1 attacker ──► Server

DDoS:
  Botnet machine 1 ──┐
  Botnet machine 2 ──┤
  Botnet machine 3 ──┼──► Server  (overwhelmed from all directions)
  Botnet machine 4 ──┤
  ...1000s more   ──┘

DDoS attack type used in this project (Friday CICIDS2017):
| DDoS UDP/TCP Flood | Thousands of bots send massive volumes of UDP or TCP packets simultaneously — saturates bandwidth completely |

# 3/ How ML detects these attacks
DoS and DDoS attacks produce statistically distinct network flow patterns compared to normal traffic:

Normal HTTPS browsing:
  Flow Duration   = long (seconds to minutes)
  Packets/s       = low (10–100)
  SYN Flag Count  = 1 (one connection handshake)
  IAT Std         = high (irregular — human behavior)
  Active/Idle     = alternating (read page → request → read → ...)

DoS Hulk:
  Flow Duration   = very short (milliseconds)
  Packets/s       = extremely high (thousands)
  SYN Flag Count  = very high (floods of connection requests)
  IAT Std         = near zero (machine-generated, perfectly regular)
  Active/Idle     = always active (never idle)

DDoS UDP Flood:
  Protocol        = UDP (no handshake at all)
  Packet Length   = tiny fixed size (same payload every packet)
  Packet Std      = near zero (all packets identical)
  TCP Flags       = all zero (UDP has no flags)

These statistical differences are what XGBoost learns to separate.

# 4/ Dataset — CICIDS2017

The Canadian Institute for Cybersecurity Intrusion Detection System 2017 dataset was created by the University of New Brunswick. A real network environment was simulated over 5 days with both normal and attack traffic captured at the packet level, then converted into network flow features using CICFlowMeter.

A network flow is all packets exchanged between two IP addresses on the same port, grouped in one direction. Instead of analyzing raw packet bytes, CICFlowMeter computes 83 statistical features per flow — timing, size, flag counts, and rate metrics.
| `Monday-WorkingHours.pcap_ISCX.csv` | Monday | BENIGN only | ~529,918 |
| `Wednesday-WorkingHours.pcap_ISCX.csv` | Wednesday | DoS attacks | ~692,703 |
| `Friday-WorkingHours.pcap_ISCX.csv` | Friday | DDoS attacks | ~225,745 |

NOTE:Each day was a separate capture session with a distinct attack scenario. Keeping them separate allows:
- Studying each attack family in isolation
- Avoiding label contamination between unrelated attack types
- Reproducing specific scenarios independently

The 83 raw features (reduced to 68 after preprocessing) fall into these categories:
| **Flow timing** | Flow Duration, Flow Packets/s, Flow Bytes/s | DoS = extremely high rates |
| **Packet length stats** | Mean, Std, Min, Max packet length | DDoS floods = tiny uniform packets |
| **Inter-arrival time (IAT)** | Flow IAT Mean, IAT Std | Attacks = near-zero Std (machine-regular) |
| **TCP flags** | SYN, ACK, FIN, RST, PSH, URG counts | SYN floods = massive SYN, near-zero ACK |
| **Window size** | Init_Win_bytes_forward/backward | Attackers often use zero/minimal window |
| **Active/Idle time** | Active Mean, Idle Mean | Attacks = always active, never idle |
| **Subflow features** | Subflow Fwd/Bwd Packets/Bytes | Flow segment behavior |

# 5/ Data Processing Pipeline
Raw CICIDS2017 CSV files cannot be fed directly into a model. The preprocessing pipeline (`preprocess.py`) resolves 8 critical data quality issues before training.

Friday_DDoS.csv  ──┐
Wednesday_DoS.csv ──┼── Merge ──► 1,448,366 rows
Monday_Normal.csv ──┘
                          │
                     Strip columns
                     Remove duplicates
                     Remove zero-variance
                     Replace inf → NaN
                     Impute NaN (median)
                     Encode labels (0/1)
                          │
                    Stratified split
                     ┌────┴─────┐
                  80% Train   20% Test
                  1,158,692   289,674
                     │
              Fit MinMaxScaler on Train
              Transform Train + Test
                     │
              Train XGBoost
                     │
              Evaluate on Test set
              (model never saw these rows)
                     │
              Save .pkl artifacts

# 6/ Model Training
XGBoost builds an ensemble of decision trees sequentially — each tree corrects the errors of the previous one. It was chosen over alternatives because:
- Handles tabular data with mixed feature scales natively
- Fast training on large datasets
- Produces probability outputs for confidence scoring

# 7/ Results on 289,674 test samples
| Metric | Score |
|--------|-------|
| Accuracy | **99.98%** |
| Precision | **99.94%** |
| Recall | **99.98%** |
| F1-Score | **99.96%** |
| ROC-AUC | **100.00%** |

> High accuracy on CICIDS2017 is expected — the statistical gap between attack and normal traffic is very large. The challenge this project addresses is the preprocessing pipeline, production deployment, and real-time inference.

# 8/ Flask API

The trained model is served through a REST API built with Flask and Gunicorn.
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Serves the frontend dashboard |
| `GET` | `/health` | Returns model status and feature count |
| `POST` | `/predict` | Classifies a single network flow |
| `POST` | `/predict/batch` | Classifies multiple flows at once |
| `GET` | `/logs` | Returns today's prediction log |

# 9/ Frontend Dashboard

A real-time security operations dashboard built in HTML/CSS/JavaScript.
- Live API connection status indicator
- Stats counters: Total Analyzed, Attacks Detected, Benign Flows, Attack Rate %
- Network flow input form with DoS and Benign simulation buttons
- Result display with ATTACK/BENIGN verdict, confidence score, and risk badge
- Confidence progress bar (0–100%)
- Live traffic chart (Chart.js) — last 20 predictions, red = attack, green = benign
- Timestamped prediction log table

# 10/ Docker Containerization

The entire application is containerized for portable, reproducible deployment.
| `Dockerfile` | Builds the image — installs dependencies, copies app, starts Gunicorn |
| `docker-compose.yml` | Orchestrates the container — port mapping, volume, restart policy |
| `.dockerignore` | Excludes CSV data files, training scripts, venv — keeps image lean |
| `requirements.txt` | Pinned Python dependencies |

# 11/ Tech Stack
| ML Model | XGBoost, scikit-learn |
| Data Processing | Pandas, NumPy |
| API | Flask, Flask-CORS, Gunicorn |
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Containerization | Docker, docker-compose |
| Dataset | CICIDS2017 (University of New Brunswick) |
| Language | Python 3.11 |
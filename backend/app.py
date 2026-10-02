import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=BASE_DIR / "frontend" / "templates",
    static_folder=BASE_DIR / "frontend" / "static"
)

CORS(app)

# LOAD MODEL & ARTIFACTS 
print("Loading model artifacts...")
model = joblib.load(BASE_DIR / "models" / "dos_detector.pkl")
scaler = joblib.load(BASE_DIR / "models" / "scaler.pkl")
feature_names = joblib.load(BASE_DIR / "models" / "feature_names.pkl")
print(f"  Model loaded. Expects {len(feature_names)} features.")

#  LOGGING SETUP 
# One JSON file per day: logs/predictions_YYYY-MM-DD.json
os.makedirs(BASE_DIR / "logs", exist_ok=True)
LOG_FILE = f"logs/predictions_{datetime.now().strftime('%Y-%m-%d')}.json"

def save_log(entry: dict) -> None:
    """Append a prediction entry to today's log file."""
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except Exception:
                logs = []
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

# ── HELPERS ──────────────────────────────────────────────────
def prepare_input(data: dict) -> np.ndarray:
    """
    Convert incoming JSON dict to a scaled numpy array.
    - Wraps dict in a 1-row DataFrame
    - Fills any missing features with 0
    - Reorders columns to match training order
    - Applies MinMaxScaler fitted during training
    """
    df = pd.DataFrame([data])
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_names]
    return scaler.transform(df)


def build_response(prediction: int, probability: float) -> dict:
    """
    Convert raw model output into a clean human-readable response.
    - prediction  : 0 (BENIGN) or 1 (ATTACK)
    - probability : confidence score from predict_proba (0.0 to 1.0)
    """
    confidence = round(float(probability), 4)
    if prediction == 1:
        risk = "HIGH" if confidence > 0.90 else "MEDIUM"
    else:
        risk = "NONE"
    return {
        "prediction" : int(prediction),
        "label"      : "ATTACK" if prediction == 1 else "BENIGN",
        "confidence" : confidence,
        "risk_level" : risk,
        "alert"      : prediction == 1
    }

# ── ROUTES ───────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend dashboard."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    """Lightweight liveness check used by Docker and the dashboard."""
    return jsonify({
        "status"  : "running",
        "model"   : "dos_detector_xgboost",
        "features": len(feature_names)
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Classify a single network flow.

    Request body (JSON):
        { "Flow Duration": 120000, "SYN Flag Count": 892, ... }

    Response:
        {
            "prediction" : 1,
            "label"      : "ATTACK",
            "confidence" : 0.9987,
            "risk_level" : "HIGH",
            "alert"      : true
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body provided"}), 400

        X           = prepare_input(data)
        prediction  = model.predict(X)[0]
        probability = model.predict_proba(X)[0][1]
        result      = build_response(int(prediction), float(probability))

        save_log({
            "timestamp"  : datetime.now().isoformat(),
            "input"      : data,
            "prediction" : result["label"],
            "confidence" : result["confidence"],
            "risk_level" : result["risk_level"]
        })

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Classify multiple network flows in one request.

    Request body (JSON):
        { "flows": [ { "Flow Duration": ..., ... }, { ... } ] }

    Response:
        {
            "total"  : 3,
            "attacks": 2,
            "benign" : 1,
            "results": [ { ...single result... }, ... ]
        }
    """
    try:
        data = request.get_json()
        if not data or "flows" not in data:
            return jsonify({"error": "Body must have a 'flows' list"}), 400

        flows = data["flows"]
        if len(flows) == 0:
            return jsonify({"error": "flows list is empty"}), 400

        df = pd.DataFrame(flows)
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0
        df = df[feature_names]
        X = scaler.transform(df)

        predictions   = model.predict(X)
        probabilities = model.predict_proba(X)[:, 1]

        results = [
            build_response(int(pred), float(prob))
            for pred, prob in zip(predictions, probabilities)
        ]

        attack_count = sum(1 for r in results if r["alert"])

        save_log({
            "timestamp" : datetime.now().isoformat(),
            "type"      : "batch",
            "total"     : len(results),
            "attacks"   : attack_count,
            "benign"    : len(results) - attack_count
        })

        return jsonify({
            "total"  : len(results),
            "attacks": attack_count,
            "benign" : len(results) - attack_count,
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/features", methods=["GET"])
def features():
    """Return the list of 68 expected feature names in training order."""
    return jsonify({
        "total"   : len(feature_names),
        "features": feature_names
    })


@app.route("/logs", methods=["GET"])
def get_logs():
    """Return today's prediction log as a JSON array."""
    if not os.path.exists(LOG_FILE):
        return jsonify([])
    with open(LOG_FILE, "r") as f:
        try:
            return jsonify(json.load(f))
        except Exception:
            return jsonify([])


# ── RUN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Starting DoS Detection API...")
    print("  http://localhost:5000/")
    print("  http://localhost:5000/health")
    print("  http://localhost:5000/predict")
    print("  http://localhost:5000/predict/batch")
    print("  http://localhost:5000/features")
    print("  http://localhost:5000/logs")
    app.run(debug=True, host="0.0.0.0", port=5000)
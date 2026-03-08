# builds the Flask app image
# ── BASE IMAGE ───────────────────────────────────────────────
# Python 3.11 slim — lightweight, no unnecessary OS packages
FROM python:3.11-slim

# ── METADATA ─────────────────────────────────────────────────
LABEL maintainer="Gadal Leila <leilagadal653@gmail.com>"
LABEL description="DoS/DDoS Network Threat Detection API"
LABEL version="1.0"

# ── ENVIRONMENT VARIABLES ────────────────────────────────────
# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Prevents Python from buffering stdout/stderr (logs appear immediately)
ENV PYTHONUNBUFFERED=1
# Flask environment
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# ── WORKING DIRECTORY ────────────────────────────────────────
WORKDIR /app

# ── INSTALL DEPENDENCIES ─────────────────────────────────────
# Copy requirements first (Docker layer caching — only reinstalls
# if requirements.txt changes, not on every code change)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── COPY APPLICATION FILES ───────────────────────────────────
# Copy source code
COPY app.py .

# Copy model artifacts (trained and fixed — baked into image)
COPY models/ ./models/

# Copy frontend
COPY templates/ ./templates/
COPY static/ ./static/

# Copy results (confusion matrix, metrics)
COPY results/ ./results/

# ── LOGS DIRECTORY ───────────────────────────────────────────
# Create logs dir — will be overridden by volume mount in compose
# but needs to exist if running container standalone
RUN mkdir -p /app/logs

# ── EXPOSE PORT ──────────────────────────────────────────────
EXPOSE 5000

# ── HEALTHCHECK ──────────────────────────────────────────────
# Docker will ping /health every 30s to verify the container is alive
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" \
    || exit 1

# ── START COMMAND ────────────────────────────────────────────
# Gunicorn = production-grade WSGI server (replaces Flask dev server)
# 2 workers, bind to all interfaces on port 5000, timeout 120s
CMD ["gunicorn", "--workers=2", "--bind=0.0.0.0:5000", "--timeout=120", "--access-logfile=-", "app:app"]
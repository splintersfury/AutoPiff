# AutoPiff Driver Monitor Service
# Standalone producer that detects new driver versions and uploads to MWDB
#
# Build from project root:
#   docker build -f services/driver-monitor/Dockerfile -t autopiff-driver-monitor .

FROM python:3.11-slim

WORKDIR /app

COPY services/driver-monitor/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/driver-monitor/sources/ /app/sources/
COPY services/driver-monitor/driver_monitor.py /app/driver_monitor.py
COPY services/driver-monitor/watchlist.yaml /app/watchlist.yaml

ENV PYTHONUNBUFFERED=1
ENV WATCHLIST_PATH=/app/watchlist.yaml

CMD ["python3", "driver_monitor.py"]

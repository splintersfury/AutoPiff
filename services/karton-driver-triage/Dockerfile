# DriverAtlas Triage Service
# Karton consumer that scores every driver's attack surface using DriverAtlas.
#
# Build from project root:
#   docker build -f services/karton-driver-triage/Dockerfile -t autopiff-driver-triage .
#
# Requires DriverAtlas source at ../DriverAtlas (via additional_contexts or COPY).

FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY services/karton-driver-triage/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy DriverAtlas package source
COPY --from=driveratlas-src driveratlas /app/driveratlas

# Copy DriverAtlas signatures
COPY --from=driveratlas-src signatures /app/driveratlas-signatures

# Copy the Karton service
COPY services/karton-driver-triage/karton_triage.py /app/karton_triage.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV DRIVERATLAS_SIGNATURES_DIR=/app/driveratlas-signatures

RUN useradd --system --no-create-home --uid 1001 appuser
USER appuser

CMD ["python3", "karton_triage.py"]

# AutoPiff Reachability Service
# Implements Stage 5 of the AutoPiff pipeline
#
# Build from project root:
#   docker build -f services/karton-reachability/Dockerfile -t autopiff-reachability .

FROM eclipse-temurin:21-jdk-jammy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY services/karton-reachability/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Download and setup Ghidra
ARG GHIDRA_VERSION=12.0.2
ARG GHIDRA_DATE=20260129
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip -O ghidra.zip && \
    unzip -q ghidra.zip && \
    mv ghidra_* ghidra && \
    rm ghidra.zip && \
    chmod +x /app/ghidra/support/analyzeHeadless

ENV GHIDRA_HOME=/app/ghidra

# Copy schemas
COPY schemas /app/schemas

# Copy Ghidra scripts
COPY ghidra/scripts/autopiff_reachability.py /app/ghidra/scripts/autopiff_reachability.py

# Copy service code
COPY services/karton-reachability/__init__.py /app/karton_reachability/__init__.py
COPY services/karton-reachability/karton_reachability.py /app/karton_reachability/karton_reachability.py

# Copy schema into service directory for local reference
RUN cp /app/schemas/reachability.schema.json /app/karton_reachability/

ENV PYTHONPATH=/app
ENV MWDB_API_URL=http://mwdb-core:8080/api/
ENV AUTOPIFF_GHIDRA_TIMEOUT=900

CMD ["python3", "-m", "karton_reachability.karton_reachability"]

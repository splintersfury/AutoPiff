# AutoPiff Patch Differ Service
# Implements Stages 1-4 of the AutoPiff pipeline
#
# Build from project root:
#   docker build -f services/karton-patch-differ/Dockerfile -t autopiff-patch-differ .

FROM eclipse-temurin:21-jdk-jammy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    unzip \
    wget \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create and activate virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies first (for layer caching)
COPY services/karton-patch-differ/requirements.txt /app/requirements.txt
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

# Copy AutoPiff rules and schemas (from project root context)
COPY rules /app/rules
COPY schemas /app/schemas

# Copy service code
COPY services/karton-patch-differ/__init__.py /app/karton_patch_differ/__init__.py
COPY services/karton-patch-differ/karton_patch_differ.py /app/karton_patch_differ/karton_patch_differ.py
COPY services/karton-patch-differ/rule_engine.py /app/karton_patch_differ/rule_engine.py
COPY services/karton-patch-differ/ExportDecompiled.py /app/ExportDecompiled.py

# Fix imports for flat structure
RUN sed -i 's/from \.rule_engine/from karton_patch_differ.rule_engine/' /app/karton_patch_differ/karton_patch_differ.py && \
    sed -i "s|os.path.join(os.path.dirname(__file__), '..', '..', 'schemas')|'/app/schemas'|" /app/karton_patch_differ/karton_patch_differ.py && \
    sed -i "s|os.path.join(os.path.dirname(__file__), '..', '..', 'rules')|'/app/rules'|" /app/karton_patch_differ/karton_patch_differ.py && \
    sed -i "s|os.path.join(os.path.dirname(__file__), \"ExportDecompiled.py\")|'/app/ExportDecompiled.py'|" /app/karton_patch_differ/karton_patch_differ.py

# Set Python path
ENV PYTHONPATH=/app

# Default environment variables
ENV MWDB_API_URL=http://mwdb-core:8080/api/
ENV AUTOPIFF_GHIDRA_TIMEOUT=2400

# Run the service
CMD ["python3", "-m", "karton_patch_differ.karton_patch_differ"]

# AutoPiff Report Service
# Implements Stage 7 of the AutoPiff pipeline
#
# Build from project root:
#   docker build -f services/karton-report/Dockerfile -t autopiff-report .

FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY services/karton-report/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy schemas
COPY schemas /app/schemas

# Copy service code
COPY services/karton-report/__init__.py /app/karton_report/__init__.py
COPY services/karton-report/karton_report.py /app/karton_report/karton_report.py
COPY services/karton-report/report_templates.py /app/karton_report/report_templates.py

# Copy schema into service directory for local reference
RUN cp /app/schemas/report.schema.json /app/karton_report/

ENV PYTHONPATH=/app
ENV AUTOPIFF_REPORT_SCHEMA=/app/karton_report/report.schema.json
ENV MWDB_API_URL=http://mwdb-core:8080/api/

CMD ["python3", "-m", "karton_report.karton_report"]

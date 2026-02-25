FROM python:3.11-slim

WORKDIR /app

COPY services/dashboard/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/dashboard/backend/ /app/backend/
# Ensure the __init__.py is present for module imports
RUN touch /app/backend/__init__.py

ENV PYTHONPATH=/app
ENV AUTOPIFF_ANALYSES_DIR=/data/analyses

RUN mkdir -p /data/analyses

RUN useradd --system --no-create-home --uid 1001 appuser
RUN chown appuser:appuser /data/analyses
USER appuser

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

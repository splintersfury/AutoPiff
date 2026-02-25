# AutoPiff Alerter Service
# Karton consumer that sends Telegram alerts for high-scoring findings
#
# Build from project root:
#   docker build -f services/autopiff-alerter/Dockerfile -t autopiff-alerter .

FROM python:3.11-slim

WORKDIR /app

COPY services/autopiff-alerter/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/autopiff-alerter/karton_alerter.py /app/karton_alerter.py

ENV PYTHONUNBUFFERED=1

RUN useradd --system --no-create-home --uid 1001 appuser
USER appuser

CMD ["python3", "karton_alerter.py"]

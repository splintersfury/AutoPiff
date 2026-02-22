FROM python:3.11-slim

WORKDIR /app

COPY services/karton-kernelsense/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY schemas /app/schemas
COPY services/karton-kernelsense/ /app/karton_kernelsense/

ENV PYTHONPATH=/app

CMD ["python3", "-m", "karton_kernelsense.karton_kernelsense"]

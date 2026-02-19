# AutoPiff Ranking Service
# Implements Stage 6 of the AutoPiff pipeline
#
# Build from project root:
#   docker build -f services/karton-ranking/Dockerfile -t autopiff-ranking .

FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY services/karton-ranking/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy schemas
COPY schemas /app/schemas

# Copy scoring model
COPY rules/scoring.yaml /app/rules/scoring.yaml

# Copy service code
COPY services/karton-ranking/__init__.py /app/karton_ranking/__init__.py
COPY services/karton-ranking/karton_ranking.py /app/karton_ranking/karton_ranking.py

# Copy schema into service directory for local reference
RUN cp /app/schemas/ranking.schema.json /app/karton_ranking/

ENV PYTHONPATH=/app
ENV AUTOPIFF_RANKING_SCHEMA=/app/karton_ranking/ranking.schema.json
ENV AUTOPIFF_SCORING_YAML=/app/rules/scoring.yaml

CMD ["python3", "-m", "karton_ranking.karton_ranking"]

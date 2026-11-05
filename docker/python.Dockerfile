# Shared runtime for all MALLYA Python services.
# Source code is bind-mounted per service (see docker-compose.yml), so each container
# only sees the directories it is meant to see (e.g. ground truth is never mounted into the worker).
FROM bitnamilegacy/minio:2025.7.23 AS minio_client

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=minio_client /opt/bitnami/minio-client/bin/mc /usr/local/bin/mc
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN git config --system --add safe.directory '*'
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/shared
WORKDIR /app

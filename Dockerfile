# -----------------------------------------------------------------------------
# Stage 1: Build & Dependency Resolution
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Hardened Production Runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create unprivileged system group and user
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -s /sbin/nologin -M socuser && \
    mkdir -p /app/data && \
    chown -R socuser:socgroup /app

# Copy isolated virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy source tree with least-privilege ownership
COPY --chown=socuser:socgroup src/ /app/src/

# Drop to unprivileged user
USER 10001:10001

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]

# ============================================================
# Dockerfile — Production multi-stage build
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runner

WORKDIR /app

# Security: non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 --no-create-home appuser

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

RUN mkdir -p /data/uploads/{images,videos,files,avatars,group_avatars,temp} && \
    chown -R appuser:appgroup /data/uploads && \
    chmod 755 /data/uploads

# Healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

ENV FLASK_DEBUG=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UPLOAD_FOLDER=/data/uploads

USER appuser

CMD ["gunicorn", "--bind", "0.0.0.0:8000", \
     "--workers", "4", "--threads", "2", \
     "--timeout", "120", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--access-logformat", "%({x-forwarded-for}i)s %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %D", \
     "--error-logfile", "-", \
     "--worker-tmp-dir", "/dev/shm", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "app:app"]

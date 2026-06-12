FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/uploads/{images,videos,files,avatars,group_avatars,temp}

EXPOSE 8000

# Production safeguards: disable Werkzeug debugger and interactive console
ENV FLASK_DEBUG=0
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Use Gunicorn with production settings, explicitly disabling the Werkzeug reloader
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--threads", "2", \
     "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", \
     "--worker-tmp-dir", "/dev/shm", \
     "--logger-class", "gunicorn.glogging.Logger", \
     "app:app"]

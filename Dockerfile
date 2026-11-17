FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOOK_ENV=production

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 hook && chown -R hook:hook /app
USER hook

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.getenv('PORT','8080'), timeout=2)" || exit 1

# Railway/Render inject $PORT. Workers share attacker state through Redis, so WEB_CONCURRENCY can be > 1.
CMD ["sh", "-c", "exec gunicorn main:app -k uvicorn.workers.UvicornWorker -w ${WEB_CONCURRENCY:-2} -b 0.0.0.0:${PORT:-8080} --forwarded-allow-ips='*' --graceful-timeout 20 --timeout 60 --access-logfile -"]

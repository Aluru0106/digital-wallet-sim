# ---------- build stage: install deps into a venv ----------
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /venv
COPY requirements.lock .
RUN /venv/bin/pip install --require-hashes --only-binary ":all:" -r requirements.lock

# ---------- runtime stage: minimal, non-root ----------
FROM python:3.12-slim
LABEL org.opencontainers.image.title="paylite-wallet" org.opencontainers.image.source="https://github.com/Aluru0106/digital-wallet-sim"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH" \
    APP_ENV=prod DB_PATH=/data/wallet.db
RUN groupadd -g 10001 app && useradd -u 10001 -g app -s /usr/sbin/nologin -M app \
 && mkdir /data && chown app:app /data \
 && rm -rf /var/lib/apt/lists/* /root/.cache
COPY --from=build /venv /venv
COPY --chown=root:root app/ /srv/app/
WORKDIR /srv
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers"]

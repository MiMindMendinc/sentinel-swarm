FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system sentinel && adduser --system --ingroup sentinel sentinel
COPY requirements.lock .
RUN python -m pip install --upgrade pip==26.2.1 && \
    python -m pip install --require-hashes -r requirements.lock
COPY --chown=sentinel:sentinel app ./app
COPY --chown=sentinel:sentinel static ./static
COPY --chown=sentinel:sentinel range ./range
RUN install -d -o sentinel -g sentinel -m 0700 /app/data

USER sentinel
EXPOSE 7777

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7777", "--no-server-header", "--no-proxy-headers", "--ws-max-size", "4096", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]

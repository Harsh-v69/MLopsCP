# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
# Optional package index override (build arg), e.g. a nearby mirror; default is official PyPI.
ARG PIP_INDEX_URL=https://pypi.org/simple
WORKDIR /w
COPY requirements-api.txt .
RUN --mount=type=cache,target=/root/.cache/pip pip wheel --default-timeout=120 --retries 8 -r requirements-api.txt -w /wheels

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/state
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /state /app/data/audit && chown -R app /state /app/data/audit
WORKDIR /app
COPY --from=build /wheels /wheels
COPY requirements-api.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements-api.txt && rm -rf /wheels
COPY requirements.txt ./requirements.txt
COPY src/ ./src/
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY security/signing_public_key.pem ./security/
COPY data/processed/ ./data/processed/
COPY data/raw/README.md ./data/raw/
COPY models/baseline_model.joblib models/baseline_model.joblib.sig models/baseline_model.joblib.dvc ./models/
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live').status==200 else 1)"
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

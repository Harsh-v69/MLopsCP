FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Requires `dvc pull` to have been run in the build context first (see
# progress.md Phase 2) - the model artifact is DVC-tracked, not committed
# to git, so it must already exist on disk for this COPY to find it.
COPY src/ src/
COPY models/baseline_model.joblib models/baseline_model.joblib

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# No manual steps after `docker run` — the model is baked into the image
# (COPY above), loaded once at process startup by src/api/main.py, which
# fails fast if it's missing (see docs/phase4_api_spec.md). Healthcheck
# hits the real /health endpoint, not just "is the process alive".
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCANNER_ENV=production \
    SCANNER_REPORT_DIR=/data/reports

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 scanner \
    && mkdir -p /data/reports \
    && chown -R scanner:scanner /app /data

COPY --chown=scanner:scanner . .
USER scanner
EXPOSE 8000
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=1", "--threads=4", "--timeout=180", "--access-logfile=-", "--error-logfile=-", "app:app"]

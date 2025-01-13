FROM python:3.11-slim

WORKDIR /app

COPY . /app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python /app/healthcheck.py || exit 1

RUN pip install --no-cache-dir -r requirements.txt .

ENTRYPOINT [ "jasapp" ]
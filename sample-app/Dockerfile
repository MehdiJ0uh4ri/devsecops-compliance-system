FROM python:3.12-slim AS base

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

USER app

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]

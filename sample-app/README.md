# sample-app

Minimal Flask service that exists purely as a scan target for
[`.github/workflows/pipeline.yml`](../.github/workflows/pipeline.yml) — Trivy,
Semgrep, Syft, and the ZAP baseline scan all run against this container. It is
not meant to be a real product.

## Endpoints

- `GET /healthz` — liveness check (used by the Dockerfile HEALTHCHECK and by
  the DAST job to confirm the container is up before scanning)
- `GET /` — service metadata
- `POST /echo` — reflects `{"message": "..."}` back HTML-escaped, which is
  what ZAP's reflected-XSS rule (`40012` in
  [`security/dast/zap-rules.tsv`](../security/dast/zap-rules.tsv)) verifies

## Local run

```bash
pip install -r requirements.txt
python app.py
# or, matching the container entrypoint:
gunicorn --bind 0.0.0.0:8080 app:app
```

## Run the same checks CI runs, locally

```bash
docker build -t sample-app:local .
docker run --rm -p 8080:8080 sample-app:local
trivy image sample-app:local
semgrep --config ../security/sast/semgrep-rules .
```

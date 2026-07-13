"""Minimal Flask service used as the scan target for the pipeline
(.github/workflows/pipeline.yml) - not a real product. Its only job is to
give Trivy/Semgrep/ZAP/Syft something real to scan so the pipeline's
detections and the noise-reduced triage aren't demonstrated against an
empty container.
"""
from __future__ import annotations

import html

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok"), 200


@app.get("/")
def index():
    return jsonify(service="sample-app", version="1.0.0"), 200


@app.post("/echo")
def echo():
    """Reflects a 'message' field back as escaped text - deliberately
    escapes user input before it could ever reach a response body, which is
    exactly what ZAP's reflected-XSS check (rule 40012 in zap-rules.tsv)
    verifies is happening."""
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", ""))
    return jsonify(message=html.escape(message)), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

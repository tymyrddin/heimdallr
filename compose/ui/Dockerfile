# heimdallr UI: the Flask surface over the OpenSearch + Sigma range.
#
# Built on the detector's toolchain (pySigma + the OpenSearch backend) so it can
# compile rules in-process, plus Flask. Logic lives in the image; data lives on
# mounts (rules/ read-write for the editor, ingest/ read-only for the explorer).
#
# Build context is the repo root (see docker-compose.yml).
FROM python:3.12-slim

RUN pip install --no-cache-dir \
      flask \
      pysigma \
      pysigma-backend-opensearch \
      pysigma-backend-splunk \
      pysigma-backend-elasticsearch

WORKDIR /opt/heimdallr
ENV PYTHONPATH=/opt/heimdallr PYTHONUNBUFFERED=1

# The UI itself.
COPY compose/ui/app.py             /opt/heimdallr/app.py
COPY compose/ui/heimdallr_ui       /opt/heimdallr/heimdallr_ui
COPY compose/ui/templates          /opt/heimdallr/templates
COPY compose/ui/static             /opt/heimdallr/static

EXPOSE 5000
CMD ["python3", "app.py"]
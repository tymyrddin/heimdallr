FROM python:3.12-slim

# heimdallr routing detector: compiles the Sigma rules with pySigma and runs them
# (plus the engine-form correlation) against OpenSearch. This is the detection
# engine for the routing substrate's thin Sigma layer; the heavy routing logic is
# in the ingest-pipeline enrichment.
RUN pip install --no-cache-dir pysigma pysigma-backend-opensearch
COPY detect.py /opt/heimdallr/detect.py
ENTRYPOINT ["python3", "/opt/heimdallr/detect.py"]

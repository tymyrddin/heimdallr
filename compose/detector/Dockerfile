FROM python:3.12-slim

# heimdallr detector: compiles the Sigma rules with pySigma and runs them
# against OpenSearch. Run on demand by `ctl detect`.
RUN pip install --no-cache-dir pysigma pysigma-backend-opensearch
COPY detect.py /opt/heimdallr/detect.py
ENTRYPOINT ["python3", "/opt/heimdallr/detect.py"]
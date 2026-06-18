FROM python:3.12-slim

# heimdallr's routing sensor. BGP is not pcap-shaped, so this feeder stands in for
# a packet sensor: it relays the raw routing telemetry under /ingest as JSON
# observations (no verdicts) and bulk-ships them to OpenSearch, where the routing
# ingest pipeline does the enrichment. Pure stdlib, no detection logic here.
COPY routing.py load.py /opt/heimdallr/
COPY entrypoint.sh /opt/heimdallr/entrypoint.sh
RUN chmod +x /opt/heimdallr/entrypoint.sh
ENTRYPOINT ["/opt/heimdallr/entrypoint.sh"]

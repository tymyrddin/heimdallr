FROM zeek/zeek:6.0

# heimdallr runs Zeek offline: it reads committed pcaps with `zeek -r` and writes
# JSON logs the collector ships to Wazuh. Nothing sniffs a live wire.
COPY scripts/ /opt/heimdallr/zeek/
COPY entrypoint.sh /opt/heimdallr/entrypoint.sh
RUN chmod +x /opt/heimdallr/entrypoint.sh
ENTRYPOINT ["/opt/heimdallr/entrypoint.sh"]

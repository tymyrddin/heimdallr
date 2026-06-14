FROM jasonish/suricata:7.0

# heimdallr runs Suricata offline: `suricata -r` over committed pcaps, writing
# eve.json the collector ships to Wazuh.
COPY rules/ /etc/suricata/heimdallr-rules/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

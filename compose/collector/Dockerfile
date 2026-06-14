FROM wazuh/wazuh-agent:4.14.5

# The collector is a Wazuh agent that tails the sensor and feeder output under
# /var/log/heimdallr and ships it to the manager. WAZUH_MANAGER (set in compose)
# drives auto-enrolment on first start.
COPY ossec.conf /var/ossec/etc/ossec.conf

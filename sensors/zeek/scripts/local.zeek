# heimdallr Zeek site policy. Kept lean: JSON output so Wazuh decodes natively,
# and the Modbus analyser left on for the OT captures (it logs modbus.log when
# Modbus traffic is present). Add per-scenario scripts alongside this file.

redef LogAscii::use_json = T;

# Modbus is part of the base protocols and logs by default. Listed here as the
# reminder that OT captures lean on it.
@load base/protocols/modbus

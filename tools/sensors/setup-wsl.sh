#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
test "$(id -u)" = 0
mkdir -p "$TASK_ROOT/sensor-data" /var/lib/edgeguard /opt/edgeguard-edr-test
if ! dpkg-query -W wazuh-agent >/dev/null 2>&1; then
  curl -fsSL https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb -o /var/lib/edgeguard/wazuh-agent.deb
  WAZUH_MANAGER=100.99.80.84 WAZUH_REGISTRATION_SERVER=100.99.80.84 WAZUH_AGENT_NAME=llm-server-wsl dpkg -i /var/lib/edgeguard/wazuh-agent.deb
fi
cp -n /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.pre-edgeguard || true
suricata-update --no-test --no-reload
cat >/etc/suricata/edgeguard.rules <<'RULE'
alert http any any -> any any (msg:"LACD controlled IDS validation"; flow:established,to_server; http.uri; content:"/lacd-ids-self-test"; classtype:misc-activity; priority:2; sid:1000001; rev:1;)
RULE
python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/suricata/suricata.yaml')
c=yaml.safe_load(p.read_text())
c['af-packet']=[{'interface':'eth0','threads':1,'cluster-id':99,'cluster-type':'cluster_flow','defrag':True,'use-mmap':True,'tpacket-v3':True}]
c['runmode']='workers'
c['stats']={'enabled':True,'interval':10}
c['stream']['memcap']='64mb'
c['flow']['memcap']='32mb'
c['rule-files']=['/var/lib/suricata/rules/suricata.rules','/etc/suricata/edgeguard.rules']
for output in c['outputs']:
    if 'eve-log' in output:
        output['eve-log']['enabled']=True
        output['eve-log']['types']=[{'alert':{'payload':True,'payload-buffer-size':'4kb','payload-printable':True,'packet':True}}, {'stats':{'totals':True,'threads':False}}]
p.write_text('%YAML 1.1\n---\n'+yaml.safe_dump(c,sort_keys=False))
p=Path('/var/ossec/etc/ossec.conf')
backup=p.with_name('ossec.conf.pre-edgeguard')
if not backup.exists(): backup.write_text(p.read_text())
text=p.read_text()
if '/opt/edgeguard-edr-test' not in text:
    text=text.replace('<syscheck>','<syscheck>\n    <directories realtime="yes" check_all="yes">/opt/edgeguard-edr-test</directories>',1)
p.write_text(text)
PY
install -m 755 "$TASK_ROOT/tools/sensors/export_sensors.py" /opt/edgeguard-export-sensors.py
cat >/etc/systemd/system/edgeguard-sensor-bridge.service <<UNIT
[Unit]
Description=EdgeGuard Suricata and Wazuh telemetry bridge
After=network-online.target suricata.service wazuh-agent.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/edgeguard-export-sensors.py $TASK_ROOT/sensor-data
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT
suricata -T -c /etc/suricata/suricata.yaml
systemctl daemon-reload
systemctl enable --now suricata wazuh-agent edgeguard-sensor-bridge
systemctl restart suricata wazuh-agent edgeguard-sensor-bridge
systemctl --no-pager --full status suricata wazuh-agent edgeguard-sensor-bridge | head -65

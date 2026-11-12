#!/usr/bin/env python3
"""WSL sensor bridge: copy only Suricata alerts and write liveness evidence.

Run by systemd as root. Never sends commands to the defense executor.
"""

import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
source = Path("/var/log/suricata/eve.json")
checkpoint = Path("/var/lib/edgeguard/sensor-offset.json")
checkpoint.parent.mkdir(parents=True, exist_ok=True)
try:
    state = json.loads(checkpoint.read_text())
except (OSError, ValueError):
    state = {}
packets = 0


def command(args):
    return subprocess.run(args, check=False, text=True, capture_output=True, timeout=12)


while True:
    try:
        if source.exists():
            stat = source.stat()
            offset = state.get("offset", 0) if state.get("inode") == stat.st_ino else 0
            if offset > stat.st_size:
                offset = 0
            with (
                source.open("rb") as reader,
                (destination / "suricata-alerts.jsonl").open("ab") as writer,
            ):
                reader.seek(offset)
                for _ in range(10000):
                    line = reader.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    raw = json.loads(line)
                    if (
                        raw.get("event_type") == "alert"
                        and int((raw.get("alert") or {}).get("severity", 3)) <= 2
                    ):
                        writer.write(line)
                    elif raw.get("event_type") == "stats":
                        packets = int(
                            (raw.get("stats", {}).get("decoder") or {}).get("pkts", 0)
                        )
                    state = {"offset": reader.tell(), "inode": stat.st_ino}
                writer.flush()
            checkpoint.write_text(json.dumps(state))
        connected = []
        result = command(
            [
                "docker",
                "exec",
                "edgeguard-wazuh-manager",
                "/var/ossec/bin/agent_control",
                "-l",
                "-j",
            ]
        )
        if result.returncode == 0:
            connected = [
                a
                for a in json.loads(result.stdout).get("data", [])
                if a.get("id") != "000" and a.get("status") == "Active"
            ]
        active = (
            command(["systemctl", "is-active", "suricata"]).stdout.strip() == "active"
        )
        payload = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "network_ids": {
                "online": active,
                "detail": f"Suricata · WSL eth0 · {packets:,} packets",
                "interface": "eth0",
                "packets": packets,
                "mode": "passive IDS",
            },
            "host_edr": {
                "online": bool(connected),
                "detail": "Wazuh · "
                + (", ".join(a["name"] for a in connected) or "no active endpoints"),
                "agents": [{"id": a["id"], "name": a["name"]} for a in connected],
            },
        }
        temporary = destination / "status.tmp"
        temporary.write_text(json.dumps(payload))
        os.replace(temporary, destination / "status.json")
    except Exception as error:  # noqa: BLE001 — preserve heartbeat retry loop after sensor/transport errors
        print(f"sensor bridge error: {error}", file=sys.stderr, flush=True)
    time.sleep(10)

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app import telemetry


class SensorTests(unittest.IsolatedAsyncioTestCase):
    def test_network_alert_retains_source_and_signature(self):
        event = {
            "event_type": "alert",
            "src_ip": "8.8.8.8",
            "alert": {"signature": "test", "severity": 2},
        }
        result = telemetry.normalize(event, "suricata")
        self.assertEqual(result["source_ip"], "8.8.8.8")
        self.assertEqual(result["severity"], "medium")
        self.assertIsNone(telemetry.normalize({"event_type": "stats"}, "suricata"))

    def test_host_address_is_never_invented_as_attacker(self):
        raw = {
            "agent": {"id": "001", "ip": "10.1.1.1"},
            "rule": {"level": 7, "description": "File modified"},
            "syscheck": {"path": "/etc/config"},
        }
        self.assertEqual(telemetry.normalize(raw, "wazuh")["source_ip"], "")
        self.assertIsNone(telemetry.normalize({"agent": {"id": "000"}}, "wazuh"))

    async def test_stale_sensor_heartbeat_cannot_show_online(self):
        with tempfile.TemporaryDirectory() as directory:
            timestamp = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
            Path(directory, "status.json").write_text(
                json.dumps(
                    {
                        "timestamp": timestamp,
                        "network_ids": {"online": True},
                        "host_edr": {"online": True},
                    }
                )
            )
            with (
                patch.object(telemetry.settings, "sensor_directory", directory),
                patch.object(telemetry.crowdsec_client, "list_alerts", return_value=[]),
            ):
                result = await telemetry.visibility()
            self.assertEqual(result["layers"]["network_ids"]["state"], "stale")
            self.assertEqual(result["layers"]["host_edr"]["state"], "stale")

    async def test_failed_persistence_preserves_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "suricata-alerts.jsonl").write_text(
                json.dumps({"event_type": "alert", "alert": {"signature": "test", "severity": 2}})
                + "\n"
            )
            redis = AsyncMock()
            redis.get.return_value = None
            with (
                patch.object(telemetry.settings, "sensor_directory", directory),
                patch.object(
                    telemetry.settings, "wazuh_alerts_path", directory + "/absent"
                ),
                patch.object(
                    telemetry.db, "insert_incident", side_effect=RuntimeError("offline")
                ),self.assertRaises(RuntimeError)
            ):
                await telemetry.ingest_once(redis)
            redis.set.assert_not_awaited()

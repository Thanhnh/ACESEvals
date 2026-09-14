"""Alert evaluator — matches events against MDATP detection rules."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


class AlertEvaluator:
    """Evaluate security events against a set of detection rules."""

    def __init__(self, rules: list[dict]):
        self.rules = rules
        self.alerts: list[dict] = []
        self._seen: set[tuple] = set()  # (timestamp, rule_id) dedup keys

    def evaluate(self, events: list[dict]) -> list[dict]:
        """Evaluate a batch of events against all rules. Returns new alerts."""
        new_alerts = []
        for event in events:
            for rule in self.rules:
                try:
                    if rule["match"](event):
                        ts = event.get("Timestamp", event.get("time", ""))
                        dedup_key = (ts, rule["id"])
                        if dedup_key in self._seen:
                            continue
                        self._seen.add(dedup_key)

                        alert = {
                            "alertId": f"alert-{len(self.alerts) + len(new_alerts) + 1}",
                            "ruleId": rule["id"],
                            "title": rule["name"],
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "mitreTechnique": rule["mitre"],
                            # Preserve the attack-capture tag from the source
                            # event so the derived SecurityAlert row stays
                            # attack-tagged (tag-authoritative capture). Fall back
                            # to the rule's MITRE id when the source was untagged.
                            "AttackTechnique": event.get("AttackTechnique", "") or rule["mitre"],
                            "timestamp": event.get("Timestamp", event.get("time",
                                         datetime.now(timezone.utc).isoformat())),
                            "deviceName": event.get("DeviceName", event.get("Computer", "")),
                            "evidence": {
                                "fileName": event.get("FileName", ""),
                                "commandLine": event.get("ProcessCommandLine", ""),
                                "accountName": event.get("AccountName",
                                               event.get("SubjectUserName", "")),
                                "actionType": event.get("ActionType", ""),
                            },
                        }
                        new_alerts.append(alert)
                except Exception:
                    continue
        self.alerts.extend(new_alerts)
        return new_alerts

    def evaluate_single(self, event: dict) -> list[dict]:
        """Evaluate a single event. Returns list of triggered alerts."""
        return self.evaluate([event])

    def get_alerts(self, severity: str | None = None) -> list[dict]:
        """Return all alerts, optionally filtered by severity."""
        if severity:
            return [a for a in self.alerts if a["severity"] == severity]
        return list(self.alerts)

    def clear(self):
        """Reset all alerts."""
        self.alerts.clear()

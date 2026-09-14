"""MDE-schema log emitter for the Windows endpoint mock.

Produces log entries conforming to Microsoft Defender for Endpoint schemas:
  - DeviceProcessEvents
  - DeviceRegistryEvents
  - DeviceFileEvents
  - DeviceNetworkEvents
  - DeviceImageLoadEvents
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .process_tree import ProcessInfo


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class MdeLogEmitter:
    """Stateless factory that stamps each log entry with device identity."""

    def __init__(self, device_id: str, device_name: str, domain: str) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.domain = domain

    # ------------------------------------------------------------------
    # DeviceProcessEvents
    # ------------------------------------------------------------------

    def device_process_event(
        self,
        process_info: ProcessInfo,
        initiating_info: ProcessInfo | None = None,
        action_type: str = "ProcessCreated",
    ) -> dict:
        return {
            "Timestamp": process_info.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": action_type,
            "FileName": process_info.file_name,
            "FolderPath": process_info.folder_path or "",
            "SHA256": process_info.sha256 or "",
            "ProcessId": process_info.pid,
            "ProcessCommandLine": process_info.command_line,
            "InitiatingProcessFileName": initiating_info.file_name if initiating_info else "",
            "InitiatingProcessId": initiating_info.pid if initiating_info else 0,
            "InitiatingProcessCommandLine": initiating_info.command_line if initiating_info else "",
            "AccountName": process_info.user,
            "AccountDomain": self.domain,
            "LogonId": 999,
            "Type": "DeviceProcessEvents",
        }

    def process_injection_event(
        self,
        source_info: ProcessInfo,
        target_info: ProcessInfo,
        technique: str,
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": "ProcessInjected",
            "FileName": target_info.file_name,
            "FolderPath": target_info.folder_path or "",
            "SHA256": "",
            "ProcessId": target_info.pid,
            "ProcessCommandLine": target_info.command_line,
            "InitiatingProcessFileName": source_info.file_name,
            "InitiatingProcessId": source_info.pid,
            "InitiatingProcessCommandLine": source_info.command_line,
            "AccountName": source_info.user,
            "AccountDomain": self.domain,
            "LogonId": 999,
            "InjectionTechnique": technique,
            "Type": "DeviceProcessEvents",
        }

    # ------------------------------------------------------------------
    # DeviceRegistryEvents
    # ------------------------------------------------------------------

    def device_registry_event(
        self,
        action: str,
        key: str,
        value_name: str | None,
        value_data: str | None,
        process_info: ProcessInfo | None = None,
        value_type: str = "REG_SZ",
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": action,
            "RegistryKey": key,
            "RegistryValueName": value_name or "",
            "RegistryValueData": value_data or "",
            "RegistryValueType": value_type,
            "InitiatingProcessFileName": process_info.file_name if process_info else "",
            "InitiatingProcessId": process_info.pid if process_info else 0,
            "Type": "DeviceRegistryEvents",
        }

    # ------------------------------------------------------------------
    # DeviceFileEvents
    # ------------------------------------------------------------------

    def device_file_event(
        self,
        action: str,
        file_name: str,
        folder_path: str,
        sha256: str | None = None,
        file_size: int | None = None,
        process_info: ProcessInfo | None = None,
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": action,
            "FileName": file_name,
            "FolderPath": folder_path,
            "SHA256": sha256 or "",
            "FileSize": file_size or 0,
            "InitiatingProcessFileName": process_info.file_name if process_info else "",
            "InitiatingProcessId": process_info.pid if process_info else 0,
            "Type": "DeviceFileEvents",
        }

    # ------------------------------------------------------------------
    # DeviceNetworkEvents
    # ------------------------------------------------------------------

    def device_network_event(
        self,
        remote_ip: str,
        remote_port: int,
        local_port: int | None = None,
        protocol: str = "tcp",
        process_info: ProcessInfo | None = None,
        remote_url: str = "",
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": "ConnectionSuccess",
            "RemoteIP": remote_ip,
            "RemotePort": remote_port,
            "RemoteUrl": remote_url,
            "LocalPort": local_port or 0,
            "Protocol": protocol,
            "InitiatingProcessFileName": process_info.file_name if process_info else "",
            "InitiatingProcessId": process_info.pid if process_info else 0,
            "Type": "DeviceNetworkEvents",
        }

    # ------------------------------------------------------------------
    # DeviceImageLoadEvents
    # ------------------------------------------------------------------

    def device_image_load_event(
        self,
        file_name: str,
        folder_path: str | None = None,
        sha256: str | None = None,
        process_info: ProcessInfo | None = None,
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "FileName": file_name,
            "FolderPath": folder_path or "",
            "SHA256": sha256 or "",
            "InitiatingProcessFileName": process_info.file_name if process_info else "",
            "InitiatingProcessId": process_info.pid if process_info else 0,
            "ActionType": "ImageLoaded",
            "Type": "DeviceImageLoadEvents",
        }

    # ------------------------------------------------------------------
    # DeviceLogonEvents
    # ------------------------------------------------------------------

    def device_logon_event(
        self,
        account_name: str,
        logon_type: str = "Network",
        remote_ip: str = "",
        remote_device: str = "",
    ) -> dict:
        return {
            "Timestamp": _utcnow(),
            "DeviceId": self.device_id,
            "DeviceName": self.device_name,
            "ActionType": "LogonSuccess",
            "LogonType": logon_type,
            "AccountName": account_name,
            "AccountDomain": self.domain,
            "RemoteIP": remote_ip,
            "RemoteDeviceName": remote_device,
            "Protocol": "SMB",
            "Type": "DeviceLogonEvents",
        }

    # ------------------------------------------------------------------
    # SecurityEvent (Windows Security log → Sentinel) — 4624 logon
    # ------------------------------------------------------------------

    def security_event_logon(
        self,
        account_name: str,
        logon_type_id: int = 3,
        source_ip: str = "",
        source_host: str = "",
        event_id: int = 4624,
    ) -> dict:
        # Flat SecurityEvent shape (the collector lifts nested ``properties`` but
        # a flat row passes through unchanged). LogonType 3 = Network.
        return {
            "TimeGenerated": _utcnow(),
            "Computer": self.device_name,
            "EventID": event_id,
            "Activity": f"{event_id} - An account was successfully logged on.",
            "Channel": "Security",
            "LogonType": logon_type_id,
            "TargetUserName": account_name,
            "TargetDomainName": self.domain,
            "IpAddress": source_ip,
            "WorkstationName": source_host,
            "Type": "SecurityEvent",
        }

    def security_event_audit_policy_change(
        self,
        account_name: str = "SYSTEM",
        category: str = "System Audit Policy",
    ) -> dict:
        """SecurityEvent 4719 — system audit policy was changed.

        The flat Sentinel artifact of defender/audit tampering (T1562.001).
        """
        return {
            "TimeGenerated": _utcnow(),
            "Computer": self.device_name,
            "EventID": 4719,
            "Activity": "4719 - System audit policy was changed.",
            "Channel": "Security",
            "SubjectUserName": account_name,
            "SubjectDomainName": self.domain,
            "CategoryId": category,
            "AuditPolicyChanges": "Success removed",
            "Type": "SecurityEvent",
        }

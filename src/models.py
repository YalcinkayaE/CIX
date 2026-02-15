import hashlib
import json
from pydantic import BaseModel, Field
from typing import Optional

class GraphReadyAlert(BaseModel):
    """
    Pydantic model for a "Graph-Ready Alert" extracting core entities.
    """
    event_id: str = Field(..., description="Unique identifier for the alert event")
    file_hash_sha256: Optional[str] = Field(None, description="SHA256 hash of the involved file")
    source_ip: Optional[str] = Field(None, description="Source IP address of the event")
    destination_ip: Optional[str] = Field(None, description="Destination IP address of the event")
    malware_family: Optional[str] = Field(None, description="Identified malware family name")
    file_name: Optional[str] = Field(None, description="Name of the file")
    file_path: Optional[str] = Field(None, description="Path of the file")
    rule_intent: Optional[str] = Field(None, description="Intent of the triggered rule")
    hostname: Optional[str] = Field(None, description="Hostname where the event occurred")
    user: Optional[str] = Field(None, description="User principal associated with the event")
    process_image: Optional[str] = Field(None, description="Process image path")
    parent_process: Optional[str] = Field(None, description="Parent process image path")
    command_line: Optional[str] = Field(None, description="Full command line")
    
    @classmethod
    def from_raw_data(cls, raw_data: dict):
        """
        Extract fields from the deserialized raw data dictionary.
        """
        def _first(*values):
            for value in values:
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                return value
            return None

        def _list_first(value):
            if isinstance(value, list) and value:
                return value[0]
            return None

        def _extract_sha256(hashes_field):
            if not isinstance(hashes_field, str):
                return None
            for chunk in hashes_field.split(","):
                token = chunk.strip()
                if token.upper().startswith("SHA256="):
                    return token.split("=", 1)[1].strip() or None
            return None

        event_id = raw_data.get("eventId") or raw_data.get("event_id") or raw_data.get("id")
        if event_id is None:
            # Deterministic fallback so malformed inputs do not crash ingestion.
            payload = json.dumps(raw_data, sort_keys=True, default=str).encode("utf-8")
            event_id = f"auto-{hashlib.sha256(payload).hexdigest()[:16]}"
        else:
            event_id = str(event_id)
        data_m = raw_data.get("data", {}) if isinstance(raw_data, dict) else {}
        raw_event = raw_data.get("raw_payload") or raw_data.get("raw_event") or {}
        if not isinstance(raw_event, dict):
            raw_event = {}
        payload_m = raw_event if raw_event else (data_m if isinstance(data_m, dict) else {})

        # Support both normalized `data.*` events and raw Sysmon/security payloads.
        file_sha256 = _first(
            data_m.get("file_hash_sha256"),
            data_m.get("sha256"),
            raw_event.get("SHA256"),
            payload_m.get("SHA256"),
            _extract_sha256(raw_event.get("Hashes")),
            _extract_sha256(payload_m.get("Hashes")),
        )
        file_path = _first(
            data_m.get("file_path"),
            raw_event.get("TargetFilename"),
            raw_event.get("Image"),
            raw_event.get("ImageLoaded"),
            raw_event.get("FilePath"),
            payload_m.get("TargetFilename"),
            payload_m.get("Image"),
            payload_m.get("ImageLoaded"),
            payload_m.get("FilePath"),
        )
        file_name = _first(
            data_m.get("file_name"),
            raw_event.get("FileName"),
            raw_event.get("Image"),
            raw_event.get("TargetFilename"),
            payload_m.get("FileName"),
            payload_m.get("Image"),
            payload_m.get("TargetFilename"),
        )
        if isinstance(file_name, str):
            file_name = file_name.replace("\\", "/").split("/")[-1]

        rule_intent = _first(
            data_m.get("rule_intent"),
            raw_event.get("RuleName"),
            raw_event.get("Category"),
            raw_event.get("EventType"),
            payload_m.get("RuleName"),
            payload_m.get("Category"),
            payload_m.get("EventType"),
        )
        hostname = _first(
            data_m.get("hostname"),
            raw_event.get("Hostname"),
            raw_event.get("host"),
            raw_event.get("ComputerName"),
            payload_m.get("Hostname"),
            payload_m.get("host"),
            payload_m.get("ComputerName"),
        )
        user = _first(
            data_m.get("user"),
            raw_event.get("User"),
            raw_event.get("AccountName"),
            raw_event.get("UserID"),
            raw_event.get("SubjectUserName"),
            payload_m.get("User"),
            payload_m.get("AccountName"),
            payload_m.get("UserID"),
            payload_m.get("SubjectUserName"),
        )
        process_image = _first(
            data_m.get("process_image"),
            raw_event.get("Image"),
            raw_event.get("ProcessName"),
            raw_event.get("SourceImage"),
            raw_event.get("New Process Name"),
            payload_m.get("Image"),
            payload_m.get("ProcessName"),
            payload_m.get("SourceImage"),
            payload_m.get("New Process Name"),
        )
        parent_process = _first(
            data_m.get("parent_process"),
            raw_event.get("ParentImage"),
            raw_event.get("ParentProcessName"),
            payload_m.get("ParentImage"),
            payload_m.get("ParentProcessName"),
        )
        command_line = _first(
            data_m.get("command_line"),
            raw_event.get("CommandLine"),
            payload_m.get("CommandLine"),
        )

        source_ip = _first(
            _list_first(data_m.get("alarm_source_ips")),
            raw_event.get("SourceAddress"),
            raw_event.get("src_ip"),
            raw_event.get("source_ip"),
            payload_m.get("SourceAddress"),
            payload_m.get("src_ip"),
            payload_m.get("source_ip"),
        )
        dest_ip = _first(
            _list_first(data_m.get("alarm_destination_ips")),
            raw_event.get("DestAddress"),
            raw_event.get("DestinationIp"),
            raw_event.get("destination_ip"),
            payload_m.get("DestAddress"),
            payload_m.get("DestinationIp"),
            payload_m.get("destination_ip"),
        )

        malware_family = _first(
            data_m.get("malware_family"),
            raw_event.get("MalwareFamily"),
            payload_m.get("MalwareFamily"),
        )
        
        return cls(
            event_id=event_id,
            file_hash_sha256=file_sha256,
            source_ip=source_ip,
            destination_ip=dest_ip,
            malware_family=malware_family,
            file_name=file_name,
            file_path=file_path,
            rule_intent=rule_intent,
            hostname=hostname,
            user=user,
            process_image=process_image,
            parent_process=parent_process,
            command_line=command_line,
        )

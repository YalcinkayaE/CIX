import json
import os
from json import JSONDecodeError
from typing import Any, Dict, List, Optional
from boto3.dynamodb.types import TypeDeserializer

class RawParser:
    """
    Utility to deserialize DynamoDB-style JSON structures (M, L, S, N) 
    into standard Python dictionaries.
    """
    def __init__(self):
        self.deserializer = TypeDeserializer()

    def deserialize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively deserialize a DynamoDB-style dictionary.
        """
        # If the top level is already DynamoDB typed (e.g., contains 'M')
        if 'M' in data and len(data) == 1:
            return self.deserializer.deserialize(data)
        
        # Otherwise, process the values
        return {k: self.deserializer.deserialize(v) for k, v in data.items()}

    def _extract_sha256(self, hashes: Optional[str]) -> Optional[str]:
        if not hashes or not isinstance(hashes, str):
            return None
        parts = hashes.split(",")
        for part in parts:
            chunk = part.strip()
            if chunk.upper().startswith("SHA256="):
                return chunk.split("=", 1)[1].strip()
        return None

    def _mordor_event_to_alert(self, event: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
        event_id = (
            event.get("eventId")
            or event.get("RecordNumber")
            or event.get("EventRecordID")
            or event.get("EventID")
            or fallback_id
        )
        file_path = event.get("TargetFilename") or event.get("Image") or event.get("Application")
        file_name = os.path.basename(file_path) if file_path else None
        command_line = event.get("CommandLine") or event.get("Process Command Line")
        process_image = event.get("Image") or event.get("ProcessName") or event.get("New Process Name")
        parent_process = event.get("ParentImage") or event.get("ParentProcessName") or event.get("Creator Process Name")
        hostname = event.get("Hostname") or event.get("Computer")
        user = event.get("User") or event.get("AccountName") or event.get("SubjectUserName")
        sha256 = self._extract_sha256(event.get("Hashes"))

        data: Dict[str, Any] = {
            "alarm_source_ips": [event.get("SourceAddress")] if event.get("SourceAddress") else [],
            "alarm_destination_ips": [event.get("DestAddress")] if event.get("DestAddress") else [],
            "file_path": file_path,
            "file_name": file_name,
            "rule_intent": event.get("Category") or event.get("EventType") or event.get("Opcode") or event.get("Task"),
            "command_line": command_line,
            "process_image": process_image,
            "parent_process": parent_process,
            "hostname": hostname,
            "user": user,
        }
        if sha256:
            data["file_hash_sha256"] = sha256

        if event.get("EventTime"):
            data["event_time"] = event.get("EventTime")
        if event.get("Message"):
            data["message"] = event.get("Message")
        if event.get("SourcePort"):
            data["source_port"] = event.get("SourcePort")
        if event.get("DestPort"):
            data["destination_port"] = event.get("DestPort")

        timestamp = (
            event.get("@timestamp")
            or event.get("EventTime")
            or event.get("EventReceivedTime")
            or event.get("UtcTime")
            or event.get("TimeCreated")
            or event.get("TimeGenerated")
            or event.get("Timestamp")
        )

        return {
            "eventId": str(event_id),
            "data": data,
            "raw_payload": event,
            "raw_event": event,
            "timestamp": timestamp,
        }

    def _looks_normalized_event(self, event: Dict[str, Any]) -> bool:
        if not isinstance(event, dict):
            return False
        # Stage-1 ingest envelope
        if "event_id" in event and (
            "raw_payload" in event or "raw_payload_ref" in event
        ):
            return True
        # Graph-ready envelope
        if "eventId" in event and "data" in event:
            return True
        return False

    def _normalize_mordor_batch(self, raw_content: Any) -> Optional[List[Dict[str, Any]]]:
        if isinstance(raw_content, dict) and isinstance(raw_content.get("events"), list):
            events = raw_content["events"]
            if events and all(
                isinstance(e, dict) and self._looks_normalized_event(e) for e in events
            ):
                return events
            return [self._mordor_event_to_alert(e, f"event_{idx}") for idx, e in enumerate(events)]

        if isinstance(raw_content, list) and raw_content:
            if any(isinstance(e, dict) and self._looks_normalized_event(e) for e in raw_content):
                return None
            if any(isinstance(e, dict) and ("EventID" in e or "RecordNumber" in e) for e in raw_content):
                return [self._mordor_event_to_alert(e, f"event_{idx}") for idx, e in enumerate(raw_content)]

        return None

    def _load_json_or_jsonl(self, file_path: str) -> Any:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        try:
            return json.loads(raw_text)
        except JSONDecodeError:
            events: List[Dict[str, Any]] = []
            for line_no, line in enumerate(raw_text.splitlines(), 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    parsed = json.loads(stripped)
                except JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSONL at line {line_no}: {exc}") from exc
                if isinstance(parsed, dict):
                    events.append(parsed)

            if events:
                return events
            raise

    def parse_file(self, file_path: str) -> list:
        """
        Load a JSON file and return a list of processed alerts.
        Supports both single object and list (batch) input.
        """
        raw_content = self._load_json_or_jsonl(file_path)

        mordor_alerts = self._normalize_mordor_batch(raw_content)
        if mordor_alerts is not None:
            alerts = mordor_alerts
        else:
            # Normalize to list
            if isinstance(raw_content, list):
                alerts = raw_content
            else:
                alerts = [raw_content]
            
        processed_alerts = []
        for alert in alerts:
            if 'data' in alert:
                # Check if it's DynamoDB typed (has 'M' wrapper)
                if isinstance(alert['data'], dict) and 'M' in alert['data']:
                    alert['data'] = self.deserialize(alert['data'])
                # If it's already a standard dict, leave it alone (mock batch case)
                
            processed_alerts.append(alert)
            
        return processed_alerts

if __name__ == "__main__":
    # Quick test
    parser = RawParser()
    try:
        cleaned = parser.parse_file("samples/cix_kernel_demo_alerts.json")
        print(json.dumps(cleaned, indent=2)[:500])
    except Exception as e:
        print(f"Error: {e}")

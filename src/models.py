from pydantic import BaseModel, Field
from typing import Optional, List

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
        event_id = raw_data.get("eventId")
        data_m = raw_data.get("data", {})
        
        # In case it was already flattened or processed
        file_sha256 = data_m.get("file_hash_sha256") or data_m.get("sha256")
        file_name = data_m.get("file_name")
        file_path = data_m.get("file_path")
        rule_intent = data_m.get("rule_intent")
        hostname = data_m.get("hostname")
        user = data_m.get("user")
        process_image = data_m.get("process_image")
        parent_process = data_m.get("parent_process")
        command_line = data_m.get("command_line")
        
        # Source IP might be in alarm_source_ips list
        source_ips = data_m.get("alarm_source_ips", [])
        source_ip = source_ips[0] if isinstance(source_ips, list) and source_ips else None

        # Destination IP might be in alarm_destination_ips list
        dest_ips = data_m.get("alarm_destination_ips", [])
        dest_ip = dest_ips[0] if isinstance(dest_ips, list) and dest_ips else None
        
        malware_family = data_m.get("malware_family")
        
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

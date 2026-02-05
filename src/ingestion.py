import json
from typing import Any, Dict
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

    def parse_file(self, file_path: str) -> list:
        """
        Load a JSON file and return a list of processed alerts.
        Supports both single object and list (batch) input.
        """
        with open(file_path, 'r') as f:
            raw_content = json.load(f)
        
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
        cleaned = parser.parse_file('soc_alert_raw.json')
        print(json.dumps(cleaned, indent=2)[:500])
    except Exception as e:
        print(f"Error: {e}")

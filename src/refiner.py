import json
import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

class IntelligenceRefiner:
    """
    Refines raw search snippets into verified AxoDen Intelligence Artifacts (IoCs).
    """
    def __init__(self):
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key:
            self.client = genai.Client(api_key=api_key)
        else:
            self.client = None

    def refine_artifacts(self, query: str, snippets: list) -> dict:
        """
        Extracts high-entropy IoCs from search snippets.
        """
        if not self.client or not snippets:
            return {"artifacts": []}

        # Contextualize for the LLM
        context = f"Query: {query}\n\nSearch Results:\n"
        for s in snippets:
            context += f"- Source: {s['url']}\n  Snippet: {s['description']}\n\n"

        prompt = f"""
        **Role:** CIX Alerts Intelligence Refiner.
        **Input:** Web search snippets related to a security lead.
        **Task:** Extract **High-Entropy Technical Artifacts** (IoCs) found in the text.
        
        **Extraction Rules:**
        1. **Extract ONLY:** C2 Domains, IP Addresses, Registry Keys, Mutexes, or specific confirmed MITRE Techniques.
        2. **Ignore (LOW_ENTROPY):** Generic descriptions, marketing text, general advice (e.g., "update your antivirus").
        3. **VSR Check:** If information contradicts known facts, flag it. 
        
        **Input Data:**
        {context}

        **Output JSON:**
        {{
          "artifacts": [
            {{
              "type": "C2_Domain | IP | RegistryKey | MITRE_Technique | VSR_CONFLICT",
              "value": "extracted_value",
              "source_url": "url_where_found",
              "confidence": "HIGH | MEDIUM"
            }}
          ]
        }}
        """

        try:
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt,
                config={
                    'response_mime_type': 'application/json'
                }
            )
            return json.loads(response.text)
        except Exception as e:
            print(f"  [!] Refiner Error: {e}")
            return {"artifacts": []}

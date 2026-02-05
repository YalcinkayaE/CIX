import os
import requests
from typing import List, Dict

class BraveChaser:
    """
    Executes automated web searches using the Brave Search API.
    """
    def __init__(self):
        self.api_key = os.getenv("BRAVE_SEARCH_API_KEY")
        self.base_url = "https://api.search.brave.com/res/v1/web/search"

    def chase_lead(self, query: str) -> List[Dict[str, str]]:
        """
        Executes a search query and returns the top 3 snippets.
        """
        if not self.api_key:
            print("  [!] Brave API Key missing. Skipping search.")
            return []

        headers = {
            "X-Subscription-Token": self.api_key,
            "Accept": "application/json"
        }
        
        # Clean query: remove site: operators if they cause issues, though usually they are fine.
        # Ensure only high value results.
        params = {
            "q": query,
            "count": 3
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                results = response.json().get("web", {}).get("results", [])
                snippets = []
                for res in results[:3]:
                    snippets.append({
                        "title": res.get("title"),
                        "url": res.get("url"),
                        "description": res.get("description")
                    })
                return snippets
            else:
                print(f"  [!] Brave Search Error: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"  [!] Brave Exception: {e}")
            return []

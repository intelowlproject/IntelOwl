import requests
from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class LeakIX(ObservableAnalyzer):
    """
    Observable analyzer for LeakIX (https://leakix.net/).
    Extracts open ports, services, data leaks, and CVEs for IPs and domains.
    """
    base_url = "https://leakix.net"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "LEAKIX_API_KEY")
        if hasattr(self, "get_secret"):
            self.api_key = self.get_secret(self.api_key_name)
        else:
            self.api_key = None

    def run(self):
        headers = {
            "Accept": "application/json",
            "User-Agent": "IntelOwl-Analyzer"
        }
        if self.api_key:
            headers["api-key"] = self.api_key

        endpoint = f"{self.base_url}/host/{self.observable_name}"

        try:
            response = requests.get(endpoint, headers=headers, timeout=15)

            # 404 indicates observable has no indexed leaks or open services
            if response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "No data found for this observable in LeakIX."
                }

            if response.status_code == 429:
                raise AnalyzerRunException("LeakIX rate limit reached. Consider configuring an API key.")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            raise AnalyzerRunException(f"Error querying LeakIX: {str(e)}")
import requests

from api_app.analyzers_manager.classes import BaseAnalyzerMixin


class FullHunt(BaseAnalyzer):
    """
    FullHunt Analyzer to enrich domains with attack surface data,
    including open ports and hostnames.
    """

    def run(self, observable: str):
        api_key = self.config.get("api_key")
        if not api_key:
            raise Exception("FullHunt API Key is missing in configuration.")

        headers = {"X-API-KEY": api_key, "User-Agent": "IntelOwl-Analyzer-FullHunt"}
        url = f"https://fullhunt.io/api/v1/domain/{observable}/details"

        try:
            # proxy & SSL Verification support
            response = requests.get(
                url,
                headers=headers,
                proxies=self.proxy_config,
                verify=self.verify_ssl,
                timeout=20,
            )

            if response.status_code == 401:
                raise Exception("Invalid FullHunt API Key")
            elif response.status_code == 404:
                return {"message": "No data found for this domain.", "status": "empty"}

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            raise Exception(f"FullHunt API request failed: {str(e)}")

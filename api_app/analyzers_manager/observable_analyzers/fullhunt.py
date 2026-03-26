from api_app.analyzers_manager.classes import ObservableAnalyzer


class FullHunt(ObservableAnalyzer):
    """
    FullHunt Analyzer to enrich domains with attack surface data,
    including open ports and hostnames.
    """

    def run(self):
        domain = self.observable_name
        api_key = self.get_config("api_key")

        if not api_key:
            raise Exception("FullHunt API Key is missing in configuration.")

        url = f"https://fullhunt.io/api/v1/domain/{domain}/details"
        headers = {
            "X-API-KEY": api_key,
            "User-Agent": "IntelOwl-Analyzer-FullHunt",
        }

        response = self.http_get(url, headers=headers, timeout=20)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise Exception("Invalid FullHunt API Key")
        elif response.status_code == 404:
            return {"message": "No data found for this domain.", "status": "empty"}

        response.raise_for_status()
        return response.json()

    def update(self):
        """
        Required by the Plugin base class.
        """
        pass

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification


class ApiVoidAnalyzer(classes.ObservableAnalyzer):
    # Using the base API URL as per documentation
    url = "https://api.apivoid.com"
    _api_key: str = None

    def update(self):
        # Implementation depends on IntelOwl configuration management
        pass

    def run(self):
        # 1. Determine the path and the JSON key name based on classification
        if self.observable_classification == Classification.DOMAIN.value:
            path = "domain-reputation"
            parameter = "host"
        elif self.observable_classification == Classification.IP.value:
            path = "ip-reputation"
            parameter = "ip"
        elif self.observable_classification == Classification.URL.value:
            path = "url-reputation"
            parameter = "url"
        else:
            raise AnalyzerConfigurationException("Observable classification not supported by APIVoid")

        # 2. Construct the full endpoint URL
        complete_url = f"{self.url}/v2/{path}"

        # 3. Define headers (including the API Key)
        headers = {"Content-Type": "application/json", "X-API-Key": self._api_key}

        # 4. Define the JSON payload
        payload = {parameter: self.observable_name}

        # 5. Execute the POST request
        r = requests.post(complete_url, headers=headers, json=payload)

        r.raise_for_status()
        return r.json()

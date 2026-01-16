# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Threatminer(classes.ObservableAnalyzer):
    url = "https://api.threatminer.org/v2/"
    rt_value: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        params = {"q": self.observable_name}
        if self.rt_value:
            params["rt"] = self.rt_value

        if self.observable_classification == Classification.DOMAIN:
            uri = "domain.php"
        elif self.observable_classification == Classification.IP:
            uri = "host.php"
        elif self.observable_classification == Classification.HASH:
            uri = "sample.php"
        else:
            raise AnalyzerRunException(
                "Unable to retrieve the uri for classification"
                f" {self.observable_classification}"
            )

        try:
            response = requests.get(self.url + uri, params=params, timeout=30)
            response.raise_for_status()

        except requests.Timeout:
            error_message = "Threatminer API request timed out — external service may be slow or unavailable."
            self.report.errors.append(error_message)
            return {"threatminer_error": error_message}

        except requests.HTTPError as http_err:
            if response is not None and response.status_code >= 500:
                error_message = (
                    f"Threatminer API returned server error ({response.status_code}) "
                    "— this is an external service issue. Try again later."
                )
                self.report.errors.append(error_message)
                return {"threatminer_error": error_message}
            raise AnalyzerRunException(f"Threatminer request failed: {str(http_err)}")

        except requests.RequestException as e:
            error_message = f"Threatminer request failed: {str(e)}"
            self.report.errors.append(error_message)
            return {"threatminer_error": error_message}

        return response.json()

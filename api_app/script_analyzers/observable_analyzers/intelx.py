import requests
import time

from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


class IntelX(ObservableAnalyzer):
    """
    Analyzer Name: `IntelX_Phonebook`\n
    Query URL: https://2.intelx.io/phonebook/search\n
    Requires API Key
    """

    base_url: str = "https://2.intelx.io/phonebook/search"

    def set_config(self, additional_config_params):
        self._rows_limit = int(additional_config_params.get("rows_limit", 100))
        self._api_key_name = additional_config_params.get(
            "api_key_name", "INTELX_API_KEY"
        )

    def run(self):
        api_key = secrets.get_secret(self._api_key_name)
        if not api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: '{self._api_key_name}'"
            )

        session = requests.Session()
        session.headers.update({"x-key": api_key, "User-Agent": "IntelOwl/v1.x"})
        params = {
            "term": self.observable_name,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": self._rows_limit,
            "timeout": 10,
            "sort": 4,
            "media": 0,
            "terminate": [],
            "target": 0,
        }
        # POST the search term --> Fetch the 'id' --> GET the results using the 'id'
        r = session.post(self.base_url, json=params)
        r.raise_for_status()
        search_id = r.json().get("id", None)
        if not search_id:
            raise AnalyzerRunException(
                f"Failed to request search. Status code: {r.status_code}."
            )
        time.sleep(15)
        r = session.get(
            f"{self.base_url}/result?id={search_id}&limit={self._rows_limit}&offset=-1"
        )
        r.raise_for_status()
        selectors = r.json()["selectors"]
        parsed_selectors = self.__pb_search_results(selectors)
        return {"id": search_id, **parsed_selectors}

    @staticmethod
    def __pb_search_results(selectors):
        """
        https://github.com/zeropwn/intelx.py/blob/master/cli/intelx.py#L89
        """
        result = {}
        for block in selectors:
            selectortypeh = block["selectortypeh"]
            if selectortypeh not in result:
                result[selectortypeh] = []
            result[selectortypeh].append(block["selectorvalue"])

        return result

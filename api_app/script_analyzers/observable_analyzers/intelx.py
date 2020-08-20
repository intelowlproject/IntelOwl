import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets

class IntelX(classes.ObservableAnalyzer):
    base_url: str = "https://2.intelx.io"

    USER_AGENT = ''
    
    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("intelx_analysis", "search")
        api_key_name = additional_config_params.get("api_key_name", "INTELX_API_KEY")
        self.__api_key = secrets.get_secret(api_key_name)
    
    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")

        if self.analysis_type == "search":

            h = {'x-key' : self.__api_key, 'User-Agent': self.USER_AGENT}
            p = {
                "term": self.observable_name,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 100,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 4,                                                                                                                                       
                "media": 0,
                "terminate": [],
                "target": 0
            }
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP, Hash, Domain, URL"
            )
        try:
            r1 = requests.post(url + '/intelligent/search', headers=h, json=p) #POST the search term ----> Fetch the 'id' -----> GET the results using the 'id'
            id=r1.json()['id']
            limit=1000
            offset=-1
            r2 = requests.get(url + f'/intelligent/search/result?id={id}&limit={limit}&offset={offset}', headers=h)
            r2.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return r2.json()

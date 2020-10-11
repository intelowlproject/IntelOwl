import datetime
import pypdns

from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class CIRCL_PDNS(classes.ObservableAnalyzer):
    def set_config(self, _):
        self.__credentials = secrets.get_secret("CIRCL_CREDENTIALS")

    def run(self):
        # You should save CIRCL credentials with this template: "<user>|<pwd>"
        if not self.__credentials:
            raise AnalyzerRunException("no credentials retrieved")

        split_credentials = self.__credentials.split("|")
        if len(split_credentials) != 2:
            raise AnalyzerRunException(
                "CIRCL credentials not properly configured."
                "Template to use: '<user>|<pwd>'"
            )

        user = split_credentials[0]
        pwd = split_credentials[1]
        pdns = pypdns.PyPDNS(basic_auth=(user, pwd))

        domain = self.observable_name
        if self.observable_classification == "url":
            domain = urlparse(self.observable_name).hostname

        result = pdns.query(domain)
        for result_item in result:
            keys_to_decode = ["time_first", "time_last"]
            for key_to_decode in keys_to_decode:
                time_extracted = result_item.get(key_to_decode, None)
                if time_extracted and isinstance(time_extracted, datetime.datetime):
                    result_item[key_to_decode] = time_extracted.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

        return result

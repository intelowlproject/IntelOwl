import pypssl

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class CIRCL_PSSL(classes.ObservableAnalyzer):
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

        pssl = pypssl.PyPSSL(basic_auth=(user, pwd))

        result = pssl.query(self.observable_name)

        certificates = []
        if result.get(self.observable_name, {}):
            certificates = list(
                result.get(self.observable_name).get("certificates", [])
            )

        parsed_result = {"ip": self.observable_name, "certificates": []}
        for cert in certificates:
            subject = (
                result.get(self.observable_name)
                .get("subjects", {})
                .get(cert, {})
                .get("values", [])
            )
            if subject:
                parsed_result["certificates"].append(
                    {"fingerprint": cert, "subject": subject[0]}
                )

        return parsed_result

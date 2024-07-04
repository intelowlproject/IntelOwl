import json
import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Ja4DB(classes.ObservableAnalyzer):
    """
    We are only checking JA4 "traditional" fingerprints here
    We should support all the JAX types as well but it is difficult
     to add them considering that
    it is not easy to understand the format and how to avoid
     to run this analyzer even in cases
    where a ja4x has not been submitted.
    This should probably require a rework where those fingerprints
     are saved in a table/collection
    """

    class NotJA4Exception(Exception):
        pass

    url = " https://ja4db.com/api/read/"

    @classmethod
    def location(cls) -> str:
        db_name = "ja4_db.json"
        return f"{settings.MEDIA_ROOT}/{db_name}"

    def check_ja4_fingerprint(self, observable: str) -> str:
        message = ""
        try:
            # https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md
            if not observable[0] in ["t", "q"]:
                # checks for protocol,
                # TCP(t) and QUIC(q) are the only supported protocols
                raise self.NotJA4Exception("only TCP and QUIC protocols are supported")
            if not observable[1:3] in ["12", "13"]:
                # checks for the version of the protocol
                raise self.NotJA4Exception("procotol version wrong")
            if not observable[3] in ["d", "i"]:
                # SNI or no SNI
                raise self.NotJA4Exception("SNI value not valid")
            if not observable[4:8].isdigit():
                # number of cipher suits and extensions
                raise self.NotJA4Exception("cipher suite must be a number")
            if len(observable) > 70 or len(observable) < 20:
                raise self.NotJA4Exception("invalid length")
            if not observable.count("_") >= 2:
                raise self.NotJA4Exception("missing underscores")
        except self.NotJA4Exception as e:
            message = f"{self.observable_name} is not valid JA4 because {e}"
            logger.info(message)

        return message

    @classmethod
    def update(cls):
        logger.info(f"Updating database from {cls.url}")
        response = requests.get(url=cls.url)
        response.raise_for_status()
        data = response.json()
        database_location = cls.location()

        with open(database_location, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info(f"Database updated at {database_location}")

    def run(self):
        reason = self.check_ja4_fingerprint(self.observable_name)
        if not reason:
            return {"not_supported": reason}

        database_location = self.location()
        if not os.path.exists(database_location):
            logger.info(
                f"Database does not exist in {database_location}, initialising..."
            )
            self.update()
        with open(database_location, "r") as f:
            db = json.load(f)
        for application in db:
            if application["ja4_fingerprint"] == self.observable_name:
                return application
        return {"found": False}

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        [
                            {
                                "application": "Nmap",
                                "library": None,
                                "device": None,
                                "os": None,
                                "user_agent_string": None,
                                "certificate_authority": None,
                                "observation_count": 1,
                                "verified": True,
                                "notes": "",
                                "ja4_fingerprint": None,
                                "ja4_fingerprint_string": None,
                                "ja4s_fingerprint": None,
                                "ja4h_fingerprint": None,
                                "ja4x_fingerprint": None,
                                "ja4t_fingerprint": "1024_2_1460_00",
                                "ja4ts_fingerprint": None,
                                "ja4tscan_fingerprint": None,
                            },
                            {
                                "application": None,
                                "library": None,
                                "device": None,
                                "os": None,
                                "user_agent_string": """Mozilla/5.0
                                (Windows NT 10.0; Win64; x64)
                                AppleWebKit/537.36 (KHTML, like Gecko)
                                Chrome/125.0.0.0
                                Safari/537.36""",
                                "certificate_authority": None,
                                "observation_count": 1,
                                "verified": False,
                                "notes": None,
                                "ja4_fingerprint": """t13d1517h2_
                                8daaf6152771_
                                b0da82dd1658""",
                                "ja4_fingerprint_string": """t13d1517h2_002f,0035,009c,
                                009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,
                                cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,
                                002d,0033,4469,fe0d,ff01_0403,0804,0401,
                                0503,0805,0501,0806,0601""",
                                "ja4s_fingerprint": None,
                                "ja4h_fingerprint": """ge11cn20enus_
                                60ca1bd65281_
                                ac95b44401d9_
                                8df6a44f726c""",
                                "ja4x_fingerprint": None,
                                "ja4t_fingerprint": None,
                                "ja4ts_fingerprint": None,
                                "ja4tscan_fingerprint": None,
                            },
                        ],
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)

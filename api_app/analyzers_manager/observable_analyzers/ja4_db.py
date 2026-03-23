import json
import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes

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
            if observable[0] not in ["t", "q"]:
                # checks for protocol,
                # TCP(t) and QUIC(q) are the only supported protocols
                raise self.NotJA4Exception("only TCP and QUIC protocols are supported")
            if observable[1:3] not in ["12", "13"]:
                # checks for the version of the protocol
                raise self.NotJA4Exception("procotol version wrong")
            if observable[3] not in ["d", "i"]:
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
            logger.info(f"Database does not exist in {database_location}, initialising...")
            self.update()
        with open(database_location, "r") as f:
            db = json.load(f)
        for application in db:
            if application["ja4_fingerprint"] == self.observable_name:
                return application
        return {"found": False}

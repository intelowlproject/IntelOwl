import json
import logging
import os
import re

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class SpamhausDropV4(classes.ObservableAnalyzer):
    url = "https://www.spamhaus.org/drop/drop_v4.json"

    @classmethod
    def location(cls) -> str:
        db_name = "drop_v4.json"
        return f"{settings.MEDIA_ROOT}/{db_name}"

    @staticmethod
    def is_valid_cidr(cidr) -> bool:
        cidr_pattern = r"^([0-9]{1,3}\.){3}[0-9]{1,3}/(0|[1-2][0-9]|3[0-2])$"
        return re.match(cidr_pattern, cidr) is not None

    def run(self):
        if not self.is_valid_cidr(self.observable_name):
            return {"not_supported": "not a valid CIDR"}
        database_location = self.location()
        if not os.path.exists(database_location):
            logger.info(
                f"Database does not exist in {database_location}, initialising..."
            )
            self.update()
        with open(database_location, "r") as f:
            db = json.load(f)
        for i in db:
            if i["cidr"] == self.observable_name:
                return {"found": True}
        return {"found": False}

    @classmethod
    def update(cls):
        logger.info(f"Updating database from {cls.url}")
        response = requests.get(url=cls.url)
        response.raise_for_status()
        data = cls.convert_to_json(response.text)
        database_location = cls.location()

        with open(database_location, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info(f"Database updated at {database_location}")

    @staticmethod
    def convert_to_json(input_string) -> dict:
        lines = input_string.strip().split("\n")
        json_objects = []
        for line in lines:
            try:
                json_obj = json.loads(line)
                json_objects.append(json_obj)
            except json.JSONDecodeError:
                raise AnalyzerRunException(
                    "Invalid JSON format in the response while updating the database"
                )

        return json_objects

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        [
                            {
                                "cidr": "1.10.16.0/20",
                                "sblid": "SBL256894",
                                "rir": "apnic",
                            },
                            {
                                "cidr": "1.19.0.0/16",
                                "sblid": "SBL434604",
                                "rir": "apnic",
                            },
                            {
                                "cidr": "1.32.128.0/18",
                                "sblid": "SBL286275",
                                "rir": "apnic",
                            },
                        ],
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)

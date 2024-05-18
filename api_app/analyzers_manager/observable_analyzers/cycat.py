import logging
import re

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MmdbServer(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for cycat api.
    """

    def update(self) -> bool:
        pass

    url: str = "https://api.cycat.org"

    def run(self):
        uuid_pattern = re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        )
        if uuid_pattern.match(self.observable_name):
            response = requests.get(
                self.url + "/lookup/" + self.observable_name,
                headers={"accept": "application/json"},
            )
        else:
            response = requests.get(
                self.url + "/search/" + self.observable_name,
                headers={"accept": "application/json"},
            )
        response.raise_for_status()
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        [
                            "24bfaeba-cb0d-4525-b3dc-507c77ecec41",
                            "b21c3b2d-02e6-45b1-980b-e69051040839",
                            "e6919abc-99f9-4c6c-95a5-14761e7b2add",
                            "cb69b20d-56d0-41ab-8440-4a4b251614d4",
                            "2dc2b567-8821-49f9-9045-8740f3d0b958",
                            "692074ae-bb62-4a5e-a735-02cb6bde458c",
                            "b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
                            "837f9164-50af-4ac0-8219-379d8a74cefc",
                            "df8b2a25-8bdf-4856-953c-a04372b1c161",
                            "8d7bd4f5-3a89-4453-9c82-2c8894d5655e",
                            "e85cae1a-bce3-4ac4-b36b-b00acac0567b",
                            "005a06c6-14bf-4118-afa0-ebcd8aebb0c9",
                            "58a3e6aa-4453-4cc8-a51f-4befe80b31a8",
                            "fb8d023d-45be-47e9-bc51-f56bcae6435b",
                            "b76b2d94-60e4-4107-a903-4a3a7622fb3b",
                            "3433a9e8-1c47-4320-b9bf-ed449061d1c3",
                            "910906dd-8c0a-475a-9cc1-5e029e2fad58",
                            "cf23bf4a-e003-4116-bbae-1ea6c558d565",
                            "13cd9151-83b7-410d-9f98-25d0f0d1d80d",
                            "afc079f3-c0ea-4096-b75d-3f05338b7f60",
                            "ef67e13e-5598-4adc-bdb2-998225874fa9",
                            "2b742742-28c3-4e1b-bab7-8350d6300fa7",
                            "be2dcee9-a7a7-4e38-afd6-21b31ecc3d63",
                            "9efb1ea7-c37b-4595-9640-b7680cd84279",
                            "c5e3cdbc-0387-4be9-8f83-ff5c0865f377",
                            "03342581-f790-4f03-ba41-e82e67392e23",
                            "4b57c098-f043-4da2-83ef-7588a6d426bc",
                            "db1355a7-e5c9-4e2c-8da7-eccf2ae9bf5c",
                            "232b7f21-adf9-4b42-b936-b9d6f7df856e",
                            "2a70812b-f1ef-44db-8578-a496a227aef2",
                            "6add2ab5-2711-4e9d-87c8-7a0be8531530",
                            "f5352566-1a64-49ac-8f7f-97e1d1a03300",
                            "b17a1a56-e99c-403c-8948-561df0cffe81",
                            "3fc9b85a-2862-4363-a64d-d692e3ffbee0",
                            "1ecfdab8-7d59-4c98-95d4-dc41970f57fc",
                            "00f90846-cbd1-4fc5-9233-df5c2bf2a662",
                            "3257eb21-f9a7-4430-8de1-d8b6e288f529",
                            "04fd5427-79c7-44ea-ae13-11b24778ff1c",
                            "65f2d882-3f41-4d48-8a06-29af77ec9f90",
                            "970a3432-3237-47ad-bcca-7d8cbb217736",
                            "b18eae87-b469-4e14-b454-b171b416bc18",
                            "dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
                            "b4d80f8b-d2b9-4448-8844-4bef777ed676",
                            "c848fcf7-6b62-4bde-8216-b6c157d48da0",
                            "648f995e-9c3a-41e4-aeee-98bb41037426",
                            "90ac9266-68ce-46f2-b24f-5eb3b2a8ea38",
                            "8dbadf80-468c-4a62-b817-4e4d8b606887",
                            "f232fa7a-025c-4d43-abc7-318e81a73d65",
                            "2e34237d-8574-43f6-aace-ae2915de8597",
                        ],
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)

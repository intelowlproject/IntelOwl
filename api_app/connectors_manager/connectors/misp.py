# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import List

import pymisp
from django.conf import settings

from api_app import helpers
from api_app.choices import Classification
from api_app.connectors_manager.classes import Connector
from tests.mock_utils import if_mock_connections, patch

INTELOWL_MISP_TYPE_MAP = {
    Classification.IP: "ip-src",
    Classification.DOMAIN: "domain",
    Classification.URL: "url",
    # "hash" (checked from helpers.get_hash_type)
    Classification.GENERIC: "text",  # misc field, so keeping text
    "file": "filename|md5",
}


def create_misp_attribute(misp_type, misp_value) -> pymisp.MISPAttribute:
    obj = pymisp.MISPAttribute()
    obj.type = misp_type
    obj.value = misp_value
    return obj


class MISP(Connector):
    tlp: str
    ssl_check: bool
    self_signed_certificate: str
    debug: bool
    _api_key_name: str
    _url_key_name: str

    @property
    def _event_obj(self) -> pymisp.MISPEvent:
        obj = pymisp.MISPEvent()
        obj.info = f"Intelowl Job-{self.job_id}"
        obj.distribution = 0  # your_organisation_only
        obj.threat_level_id = 4  # undefined
        obj.analysis = 2  # completed
        obj.add_tag("source:intelowl")
        obj.add_tag(f"tlp:{self.tlp}")  # tlp tag for sharing

        # Add tags from Job
        for tag in self._job.tags.all():
            obj.add_tag(f"intelowl-tag:{tag.label}")

        return obj

    @property
    def _base_attr_obj(self) -> pymisp.MISPAttribute:
        if self._job.is_sample:
            _type = INTELOWL_MISP_TYPE_MAP["file"]
            value = f"{self._job.analyzable.name}|{self._job.analyzable.md5}"
        else:
            _type = self._job.analyzable.classification
            value = self._job.analyzable.name
            if _type == Classification.HASH:
                matched_type = helpers.get_hash_type(value)
                matched_type.replace("-", "")  # convert sha-x to shax
                _type = matched_type if matched_type is not None else "text"
            else:
                _type = INTELOWL_MISP_TYPE_MAP[_type]

        obj = create_misp_attribute(_type, value)
        analyzers_names = self._job.analyzers_to_execute.all().values_list("name", flat=True)
        obj.comment = f"Analyzers Executed: {', '.join(analyzers_names)}"
        return obj

    @property
    def _secondary_attr_objs(self) -> List[pymisp.MISPAttribute]:
        obj_list = []
        if self._job.is_sample:
            # mime-type
            obj_list.append(create_misp_attribute("mime-type", self._job.analyzable.mimetype))
        return obj_list

    @property
    def _link_attr_obj(self) -> pymisp.MISPAttribute:
        """
        Returns attribute linking analysis on IntelOwl instance
        """
        obj = pymisp.MISPAttribute()
        obj.type = "link"
        obj.value = f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}"
        obj.comment = "View Analysis on IntelOwl"
        obj.disable_correlation = True

        return obj

    def run(self):
        ssl_param = (
            f"{settings.PROJECT_LOCATION}/configuration/misp_ssl.crt"
            if self.ssl_check and self.self_signed_certificate
            else self.ssl_check
        )
        misp_instance = pymisp.PyMISP(
            url=self._url_key_name,
            key=self._api_key_name,
            ssl=ssl_param,
            debug=self.debug,
            timeout=5,
        )

        # get event and attributes
        event = self._event_obj
        attributes = [
            self._base_attr_obj,
            *self._secondary_attr_objs,
            self._link_attr_obj,
        ]

        # append attribute name to event info
        event.info += f": {self._base_attr_obj.value}"

        # add event to MISP Instance
        misp_event = misp_instance.add_event(event, pythonify=True)
        # add attributes to event on MISP Instance
        for attr in attributes:
            misp_instance.add_attribute(misp_event.id, attr)

        return misp_instance.get_event(misp_event.id)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "pymisp.PyMISP",
                    side_effect=MockPyMISP,
                )
            )
        ]
        return super()._monkeypatch(patches=patches)


# Mocks
class MockUpMISPElement:
    """
    Mock element(event/attribute) for testing
    """

    id: int = 1


class MockPyMISP:
    """
    Mock PyMISP instance for testing
     methods which require connection to a MISP instance
    """

    def __init__(self, *args, **kwargs) -> None:
        pass

    @staticmethod
    def add_event(*args, **kwargs) -> MockUpMISPElement:
        return MockUpMISPElement()

    @staticmethod
    def add_attribute(*args, **kwargs) -> MockUpMISPElement:
        return MockUpMISPElement()

    @staticmethod
    def get_event(event_id) -> dict:
        return {"Event": {"id": event_id}}

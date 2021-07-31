# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

import hashlib
import pymisp
from typing import List

from tests.mock_utils import patch, if_mock_connections
from api_app.connectors_manager.classes import Connector
from api_app import helpers


INTELOWL_MISP_TYPE_MAP = {
    "ip": "ip-src",
    "domain": "domain",
    "url": "url",
    # "hash" (checked from helpers.get_hash_type)
    "generic": "text",  # misc field, so keeping text
    "file": "filename|md5",
}


class MISP(Connector):
    def set_params(self, params):
        self.ssl_check = params.get("ssl_check", True)
        self.debug = params.get("debug", False)
        self.tlp = params.get("tlp", "white")
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

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

    def _get_attr_obj(self, type, value) -> pymisp.MISPAttribute:
        obj = pymisp.MISPAttribute()
        obj.type = type
        obj.value = value
        return obj

    @property
    def _base_attr_obj(self) -> pymisp.MISPAttribute:
        if self._job.is_sample:
            type = INTELOWL_MISP_TYPE_MAP["file"]
            binary = helpers.get_binary(self.job_id)
            md5 = hashlib.md5(binary).hexdigest()
            value = f"{self._job.file_name}|{md5}"
        else:
            type = self._job.observable_classification
            value = self._job.observable_name
            if type == "hash":
                matched_type = helpers.get_hash_type(value)
                matched_type.replace("-", "")  # convert sha-x to shax
                type = matched_type if matched_type is not None else "text"
            else:
                type = INTELOWL_MISP_TYPE_MAP[type]

        obj = self._get_attr_obj(type, value)
        obj.comment = f"Analyzers Executed: {self._job.analyzers_to_execute}"
        return obj

    @property
    def _secondary_attr_objs(self) -> List[pymisp.MISPAttribute]:
        obj_list = []
        if self._job.is_sample:
            # mime-type
            obj_list.append(self._get_attr_obj("mime-type", self._job.file_mimetype))
        return obj_list

    @property
    def _link_attr_obj(self) -> pymisp.MISPAttribute:
        """
        Returns attribute linking analysis on IntelOwl instance
        """
        obj = pymisp.MISPAttribute()
        obj.type = "link"
        obj.value = f"{settings.WEB_CLIENT_URL}/pages/scan/result/{self.job_id}"
        obj.comment = "View Analysis on IntelOwl"
        obj.disable_correlation = True

        return obj

    def run(self):
        misp_instance = pymisp.PyMISP(
            url=self.__url_name,
            key=self.__api_key,
            ssl=self.ssl_check,
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
class MockMISPElement:
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

    def add_event(self, *args, **kwargs) -> MockMISPElement:
        return MockMISPElement()

    def add_attribute(self, *args, **kwargs) -> MockMISPElement:
        return MockMISPElement()

    def get_event(self, event_id) -> dict:
        return {"Event": {"id": event_id}}

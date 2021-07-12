# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import pymisp

from ..classes import Connector


# TODO: identify type of hash
INTELOWL_MISP_TYPE_MAP = {
    "ip": "ip-src",
    "domain": "domain",
    "url": "url",
    "hash": "md5",
    "general": "text",  # misc field, so keeping text
    "file": "filename",
}


class MISP(Connector):
    def set_params(self, params):
        self.ssl_check = params.get("ssl_check", True)
        self.debug = params.get("debug", False)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    @property
    def _event_obj(self):
        obj = pymisp.MISPEvent()
        obj.info = f"Intelowl Analysis: {self.obs_name}"
        obj.distribution = 0  # your_organisation_only
        obj.threat_level_id = 4  # undefined
        obj.analysis = 2  # completed
        obj.add_tag("intelowl")

        # TODO: Add tags from Job

        return obj

    @property
    def _base_attr_obj(self):
        if self._job.is_sample:
            type = "file"
            value = f"{self._job.file_name} ({self._job.file_mimetype})"
        else:
            type = self._job.observable_classification
            value = self._job.observable_name

        obj = pymisp.MISPAttribute()
        obj.type = INTELOWL_MISP_TYPE_MAP[type]
        obj.value = value
        obj.add_tag(f"intelowl:{self.obs_type}")

        return obj

    @property
    def _link_attr_obj(self):
        """
        Returns attribute linking analysis on IntelOwl instance
        """
        obj = pymisp.MISPAttribute()
        obj.type = "link"
        # TODO: get instance url
        obj.value = f"http://localhost/pages/scan/result/{self.job_id}"
        obj.comment = "View Analysis on IntelOwl"

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
        attributes = [self._base_attr_obj, self._link_attr_obj]

        # add event to MISP Instance
        misp_event = misp_instance.add_event(event, pythonify=True)
        # add attributes to event on MISP Instance
        for attr in attributes:
            misp_instance.add_attribute(misp_event.id, attr)

        return misp_instance.get_event(misp_event.id)

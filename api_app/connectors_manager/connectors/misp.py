# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import List

import pymisp
from django.conf import settings

from api_app import helpers
from api_app.choices import Classification
from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.exceptions import ConnectorRunException

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
                # convert sha-x to shax
                _type = matched_type.replace("-", "") if matched_type is not None else "text"
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

    def _handle_misp_errors(self, errors):
        error_str = str(errors)

        debug_info = (
            f" [debug: PyMISP version={pymisp.__version__},"
            f" ssl_check={self.ssl_check},"
            f" url={self._url_key_name}]"
            if self.debug
            else ""
        )

        if "The plain HTTP request was sent to HTTPS port" in error_str:
            raise ConnectorRunException(
                "MISP connection failed: You are trying to send a plain HTTP request to an HTTPS port. "
                "Please change your MISP URL in the plugin configuration from 'http://' to 'https://'."
                f"{debug_info}"
            )
        else:
            raise ConnectorRunException(f"{errors}{debug_info}")

    def run(self):
        ssl_param = (
            f"{settings.PROJECT_LOCATION}/configuration/misp_ssl.crt"
            if self.ssl_check and self.self_signed_certificate
            else self.ssl_check
        )

        try:
            misp_instance = pymisp.PyMISP(
                url=self._url_key_name,
                key=self._api_key_name,
                ssl=ssl_param,
                debug=self.debug,
                timeout=5,
            )
        except Exception as e:
            self._handle_misp_errors(f"MISP initialization failed: {str(e)}")

        # get event and attributes
        event = self._event_obj
        attributes = [
            self._base_attr_obj,
            *self._secondary_attr_objs,
            self._link_attr_obj,
        ]

        # append attribute name to event info
        event.info += f": {self._base_attr_obj.value}"

        # bulk: attach all attributes to the event object before sending
        for attr in attributes:
            event.add_attribute(
                attr.type,
                attr.value,
                **{k: v for k, v in attr.to_dict().items() if k not in ("type", "value", "uuid")},
            )

        # single request — event + all attributes sent together
        try:
            misp_event = misp_instance.add_event(event, pythonify=True)
        except Exception as e:
            self._handle_misp_errors(f"MISP add event failed: {str(e)}")

        if isinstance(misp_event, dict):
            errors = misp_event.get("errors", [])
            if errors:
                self._handle_misp_errors(errors)

        return misp_instance.get_event(misp_event.id)

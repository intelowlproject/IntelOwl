# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List

import pymisp
from django.conf import settings

from api_app.choices import Classification
from api_app.connectors_manager.classes import CTIConnector
from api_app.connectors_manager.exceptions import ConnectorRunException

logger = logging.getLogger(__name__)

INTELOWL_MISP_TYPE_MAP = {
    Classification.IP: "ip-src",
    Classification.DOMAIN: "domain",
    Classification.URL: "url",
    # "hash" (checked from self.hash_type)
    Classification.GENERIC: "text",  # misc field, so keeping text
    Classification.FILE: "filename|md5",
}


def create_misp_attribute(misp_type, misp_value) -> pymisp.MISPAttribute:
    obj = pymisp.MISPAttribute()
    obj.type = misp_type
    obj.value = misp_value
    return obj


class MISP(CTIConnector):
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
        for label in self.tag_labels:
            obj.add_tag(f"intelowl-tag:{label}")

        # Add enrichment tags from data model when available
        if self.has_data_model:
            if self.evaluation:
                obj.add_tag(f"evaluation:{self.evaluation}")
            if self.malware_family:
                obj.add_tag(f"malware-family:{self.malware_family}")
            if self.kill_chain_phase:
                obj.add_tag(f"kill-chain:{self.kill_chain_phase}")
            if self.reliability:
                obj.add_tag(f"reliability:{self.reliability}")

        return obj

    @property
    def _base_attr_obj(self) -> pymisp.MISPAttribute:
        if self.classification == Classification.FILE:
            _type = INTELOWL_MISP_TYPE_MAP[Classification.FILE]
            value = f"{self.observable_name}|{self._job.analyzable.md5}"
        else:
            value = self.observable_name
            if self.hash_type is not None:
                # convert sha-x to shax
                _type = self.hash_type.replace("-", "")
            else:
                _type = INTELOWL_MISP_TYPE_MAP.get(self.classification, "text")

        obj = create_misp_attribute(_type, value)
        obj.comment = f"Analyzers Executed: {', '.join(self.analyzer_names)}"
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
        obj.value = self.analysis_url
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

    def health_check(self, user=None) -> tuple:
        if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
            return True, "Mock connection successful"

        params = self._config.parameters.annotate_configured(self._config, user).annotate_value_for_user(
            self._config, user
        )

        url = None
        key = None

        ssl_check = True
        self_signed_certificate = False

        for param in params:
            if param.name == "url_key_name":
                url = param.value
            elif param.name == "api_key_name":
                key = param.value
            elif param.name == "ssl_check":
                ssl_check = param.value
            elif param.name == "self_signed_certificate":
                self_signed_certificate = param.value

        if not url:
            logger.info("Healthcheck failed: Missing config url")
            return False, "Missing config url"
        if not key:
            logger.info("Healthcheck failed: Missing config api key")
            return False, "Missing config api key"

        ssl_param = (
            f"{settings.PROJECT_LOCATION}/configuration/misp_ssl.crt"
            if ssl_check and self_signed_certificate
            else ssl_check
        )

        try:
            misp = pymisp.PyMISP(
                url=url,
                key=key,
                ssl=ssl_param,
                debug=False,
                timeout=5,
            )

            # PyMISP has a property misp_instance_version
            # that makes a GET request to servers/getVersion
            # using valid API key and returns the version of
            # the MISP instance if the connection is successful
            # Refs: https://pymisp.readthedocs.io/en/latest/modules.html?#pymisp.PyMISP.misp_instance_version
            misp.misp_instance_version
            return True, "Connected successfully"

        except Exception as e:
            logger.info(f"MISP health check failed: {e}")
            return False, f"Connection failed: {e}"

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

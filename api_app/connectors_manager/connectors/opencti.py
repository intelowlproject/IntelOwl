# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

from pycti.api.opencti_api_client import File
import pycti

from tests.mock_utils import patch, if_mock_connections
from api_app import helpers
from api_app.connectors_manager import classes


INTELOWL_OPENCTI_TYPE_MAP = {
    "ip": {
        "v4": "ipv4-addr",
        "v6": "ipv6-addr",
    },
    "domain": "domain-name",
    "url": "url",
    # type hash is combined with file
    "generic": "x-opencti-text",  # misc field, so keeping text
    "file": "file",  # hashes: md5, sha-1, sha-256
}


class OpenCTI(classes.Connector):
    def set_params(self, params):
        self.ssl_verify = params.get("ssl_verify", True)
        self.tlp = params.get(
            "tlp", {"type": "white", "color": "#FFFFFF", "x_opencti_order": 0}
        )
        self.proxies = params.get("proxies", {})
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def get_observable_type(self) -> str:
        if self._job.is_sample:
            obs_type = INTELOWL_OPENCTI_TYPE_MAP["file"]
        elif self._job.observable_classification == "hash":
            matched_hash_type = helpers.get_hash_type(self._job.observable_name)
            if matched_hash_type in [
                "md5",
                "sha-1",
                "sha-256",
            ]:  # sha-512 not supported
                obs_type = INTELOWL_OPENCTI_TYPE_MAP["file"]
            else:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP["generic"]  # text
        elif self._job.observable_classification == "ip":
            ip_version = helpers.get_ip_version(self._job.observable_name)
            if ip_version == 4 or ip_version == 6:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP["ip"][f"v{ip_version}"]  # v4/v6
            else:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP["generic"]  # text
        else:
            obs_type = INTELOWL_OPENCTI_TYPE_MAP[self._job.observable_classification]

        return obs_type

    def generate_observable_data(self) -> dict:
        observable_data = {"type": self.get_observable_type()}
        if self._job.is_sample:
            observable_data["name"] = self._job.file_name
            observable_data["hashes"] = {
                "md5": self._job.md5,
                "sha-1": self._job.sha1,
                "sha-256": self._job.sha256,
            }
        elif (
            self._job.observable_classification == "hash"
            and observable_data["type"] == "file"
        ):
            # add hash instead of value
            matched_type = helpers.get_hash_type(self._job.observable_name)
            observable_data["hashes"] = {matched_type: self._job.observable_name}
        else:
            observable_data["value"] = self._job.observable_name

        return observable_data

    @property
    def organization_id(self) -> str:
        # Create author (if not exists); else update
        org = pycti.Identity(self.opencti_instance).create(
            type="Organization",
            name="IntelOwl",
            description=(
                "Intel Owl is an Open Source Intelligence, or OSINT solution"
                " to get threat intelligence data about a specific file, an IP or a"
                " domain from a single API at scale. [Visit the project on GitHub]"
                "(https://github.com/intelowlproject/IntelOwl/)"
            ),
            update=True,  # just in case the description is updated in future
        )
        return org["id"]

    @property
    def marking_definition_id(self) -> str:
        # Create the marking definition (if not exists)
        md = pycti.MarkingDefinition(self.opencti_instance).create(
            definition_type="TLP",
            definition=f"TLP:{self.tlp['type'].upper()}",
            x_opencti_color=self.tlp["color"].lower(),
            x_opencti_order=self.tlp["x_opencti_order"],
        )
        return md["id"]

    def run(self):
        # set up client
        self.opencti_instance = pycti.OpenCTIApiClient(
            url=self.__url_name,
            token=self.__api_key,
            ssl_verify=self.ssl_verify,
            proxies=self.proxies,
        )

        # Entities in OpenCTI are created only if they don't exist
        # create queries will return the existing entity in that case
        # use update (default: false) to update the entity if exists

        # Create the observable (if not exists with the given type and values)
        observable_data = self.generate_observable_data()
        observable = pycti.StixCyberObservable(self.opencti_instance, File).create(
            observableData=observable_data,
            createdBy=self.organization_id,
            objectMarking=self.marking_definition_id,
        )

        # Create labels from Job tags (if not exists)
        label_ids = []
        for tag in self._job.tags.all():
            label = pycti.Label(self.opencti_instance).create(
                value=f"intelowl-tag:{tag.label}",
                color=tag.color,
            )
            label_ids.append(label["id"])

        # Create the report
        report = pycti.Report(self.opencti_instance).create(
            name=f"IntelOwl Job-{self.job_id}",
            description=(
                f"This is IntelOwl's analysis report for Job: {self.job_id}."
                # comma separate analyzers executed
                f" Analyzers Executed: {', '.join(self._job.analyzers_to_execute)}"
            ),
            published=self._job.received_request_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=["internal-report"],
            createdBy=self.organization_id,
            objectMarking=self.marking_definition_id,
            objectLabel=label_ids,
            x_opencti_report_status=2,  # Analyzed
        )
        # Create the external reference
        external_reference = pycti.ExternalReference(self.opencti_instance).create(
            source_name="IntelOwl Analysis",
            description="View analysis report on the IntelOwl instance",
            url=f"{settings.WEB_CLIENT_URL}/pages/scan/result/{self.job_id}",
        )
        # Add the external reference to the report
        pycti.StixDomainObject(self.opencti_instance, File).add_external_reference(
            id=report["id"], external_reference_id=external_reference["id"]
        )

        # Link Observable and Report
        pycti.Report(self.opencti_instance).add_stix_object_or_stix_relationship(
            id=report["id"], stixObjectOrStixRelationshipId=observable["id"]
        )

        return {
            "observable": pycti.StixCyberObservable(self.opencti_instance, File).read(
                id=observable["id"]
            ),
            "report": pycti.Report(self.opencti_instance).read(id=report["id"]),
        }

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("pycti.OpenCTIApiClient", return_value=None),
                patch("pycti.Identity.create", return_value={"id": 1}),
                patch("pycti.MarkingDefinition.create", return_value={"id": 1}),
                patch("pycti.StixCyberObservable.create", return_value={"id": 1}),
                patch("pycti.Label.create", return_value={"id": 1}),
                patch("pycti.Report.create", return_value={"id": 1}),
                patch("pycti.ExternalReference.create", return_value={"id": 1}),
                patch(
                    "pycti.StixDomainObject.add_external_reference", return_value=None
                ),
                patch(
                    "pycti.Report.add_stix_object_or_stix_relationship",
                    return_value=None,
                ),
                patch("pycti.StixCyberObservable.read", return_value={"id": 1}),
                patch("pycti.Report.read", return_value={"id": 1}),
            )
        ]
        return super()._monkeypatch(patches=patches)

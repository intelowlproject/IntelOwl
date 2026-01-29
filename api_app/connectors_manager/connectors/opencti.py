# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import Dict

import pycti
from django.conf import settings
from pycti.api.opencti_api_client import File

from api_app import helpers
from api_app.choices import Classification
from api_app.connectors_manager import classes
from tests.mock_utils import if_mock_connections, patch

INTELOWL_OPENCTI_TYPE_MAP = {
    Classification.IP: {
        "v4": "ipv4-addr",
        "v6": "ipv6-addr",
    },
    Classification.DOMAIN: "domain-name",
    Classification.URL: "url",
    # type hash is missing because it is combined with "file"
    # "generic" is misc field, so keeping text
    Classification.GENERIC: "x-opencti-text",
    "file": "file",  # hashes: md5, sha-1, sha-256
}


class OpenCTI(classes.Connector):
    ssl_verify: bool
    tlp: dict
    proxies: str
    _url_key_name: str
    _api_key_name: str

    def get_observable_type(self) -> str:
        if self._job.is_sample:
            obs_type = INTELOWL_OPENCTI_TYPE_MAP["file"]
        elif self._job.analyzable.classification == Classification.HASH:
            matched_hash_type = helpers.get_hash_type(self._job.analyzable.name)
            if matched_hash_type in [
                "md5",
                "sha-1",
                "sha-256",
            ]:  # sha-512 not supported
                obs_type = INTELOWL_OPENCTI_TYPE_MAP["file"]
            else:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP[Classification.GENERIC]  # text
        elif self._job.analyzable.classification == Classification.IP:
            ip_version = helpers.get_ip_version(self._job.analyzable.name)
            if ip_version in [4, 6]:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP[Classification.IP][f"v{ip_version}"]  # v4/v6
            else:
                obs_type = INTELOWL_OPENCTI_TYPE_MAP[Classification.GENERIC]  # text
        else:
            obs_type = INTELOWL_OPENCTI_TYPE_MAP[self._job.analyzable.classification]

        return obs_type

    def generate_observable_data(self) -> dict:
        observable_data = {"type": self.get_observable_type()}
        if self._job.is_sample:
            observable_data["name"] = self._job.analyzable.name
            observable_data["hashes"] = {
                "md5": self._job.analyzable.md5,
                "sha-1": self._job.analyzable.sha1,
                "sha-256": self._job.analyzable.sha256,
            }
        elif self._job.analyzable.classification == Classification.HASH and observable_data["type"] == "file":
            # add hash instead of value
            matched_type = helpers.get_hash_type(self._job.analyzable.name)
            observable_data["hashes"] = {matched_type: self._job.analyzable.name}
        else:
            observable_data["value"] = self._job.analyzable.name

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

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.ssl_verify is None:
            self.ssl_verify = False

    def run(self):
        # set up client
        self.opencti_instance = pycti.OpenCTIApiClient(
            url=self._url_key_name,
            token=self._api_key_name,
            ssl_verify=self.ssl_verify,
            proxies=self.proxies,
        )

        # Entities in OpenCTI are created only if they don't exist
        # create queries will return the existing entity in that case
        # use update (default: False) to update the entity if exists

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
                " Analyzers Executed:"
                f" {', '.join(list(self._job.analyzers_to_execute.all().values_list('name', flat=True)))}"  # noqa
            ),
            published=self._job.received_request_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=["internal-report"],
            createdBy=self.organization_id,
            objectMarking=self.marking_definition_id,
            objectLabel=label_ids,
            x_opencti_report_status=2,  # Analyzed
        )
        # Create the external reference
        external_reference = pycti.ExternalReference(self.opencti_instance, None).create(
            source_name="IntelOwl Analysis",
            description="View analysis report on the IntelOwl instance",
            url=f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}",
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
            "observable": pycti.StixCyberObservable(self.opencti_instance, File).read(id=observable["id"]),
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
                patch("pycti.StixDomainObject.add_external_reference", return_value=None),
                patch(
                    "pycti.Report.add_stix_object_or_stix_relationship",
                    return_value=None,
                ),
                patch("pycti.StixCyberObservable.read", return_value={"id": 1}),
                patch("pycti.Report.read", return_value={"id": 1}),
            )
        ]
        return super()._monkeypatch(patches=patches)

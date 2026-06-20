# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import Dict

import pycti
from django.conf import settings
from pycti.api.opencti_api_client import File

from api_app import helpers
from api_app.choices import Classification
from api_app.connectors_manager import classes

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
        # Idempotent author organization for all OpenCTI objects.
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
        if isinstance(org, dict):
            return org.get("id")
        return None

    @property
    def marking_definition_id(self) -> str:
        # Idempotent TLP marking used on all OpenCTI objects.
        md = pycti.MarkingDefinition(self.opencti_instance).create(
            definition_type="TLP",
            definition=f"TLP:{self.tlp['type'].upper()}",
            x_opencti_color=self.tlp["color"].lower(),
            x_opencti_order=self.tlp["x_opencti_order"],
        )
        if isinstance(md, dict):
            return md.get("id")
        return None

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.ssl_verify is None:
            self.ssl_verify = False

    def _create_observable(self, created, org_id, marking_id):
        observable_data = self.generate_observable_data()
        observable = pycti.StixCyberObservable(self.opencti_instance, File).create(
            observableData=observable_data,
            createdBy=org_id,
            objectMarking=marking_id,
        )
        observable_id = observable["id"] if isinstance(observable, dict) and "id" in observable else None
        created["observable"] = observable_id
        return observable_id

    def _create_labels(self, created):
        label_ids = []
        for tag in self._job.tags.all():
            label = pycti.Label(self.opencti_instance).create(
                value=f"intelowl-tag:{tag.label}",
                color=tag.color,
            )
            if not isinstance(label, dict) or "id" not in label:
                raise ValueError("Invalid response from OpenCTI Label.create")
            label_id = label["id"]
            created["labels"].append(label_id)
            label_ids.append(label_id)
        return label_ids

    def _create_report(self, created, org_id, marking_id, label_ids):
        report = pycti.Report(self.opencti_instance).create(
            name=f"IntelOwl Job-{self.job_id}",
            description=(
                f"This is IntelOwl's analysis report for Job: {self.job_id}."
                " Analyzers Executed:"
                f" {', '.join(list(self._job.analyzers_to_execute.all().values_list('name', flat=True)))}"
            ),
            published=self._job.received_request_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=["internal-report"],
            createdBy=org_id,
            objectMarking=marking_id,
            objectLabel=label_ids,
            x_opencti_report_status=2,
        )
        if not isinstance(report, dict) or "id" not in report:
            created["report"] = None
            raise ValueError("Invalid response from OpenCTI Report.create")
        report_id = report["id"]
        created["report"] = report_id
        return report_id

    def _create_external_reference(self, created):
        external_reference = pycti.ExternalReference(self.opencti_instance, None).create(
            source_name="IntelOwl Analysis",
            description="View analysis report on the IntelOwl instance",
            url=f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}",
        )
        if not isinstance(external_reference, dict) or "id" not in external_reference:
            created["external_reference"] = None
            raise ValueError("Invalid response from OpenCTI ExternalReference.create")
        external_ref_id = external_reference["id"]
        created["external_reference"] = external_ref_id
        return external_ref_id

    def _link_report_entities(self, report_id, observable_id, external_ref_id):
        if report_id is not None and external_ref_id is not None:
            pycti.StixDomainObject(self.opencti_instance, File).add_external_reference(
                id=report_id, external_reference_id=external_ref_id
            )
        if report_id is not None and observable_id is not None:
            pycti.Report(self.opencti_instance).add_stix_object_or_stix_relationship(
                id=report_id, stixObjectOrStixRelationshipId=observable_id
            )

    def run(self):
        # Initialize OpenCTI client for this run.
        self.opencti_instance = pycti.OpenCTIApiClient(
            url=self._url_key_name,
            token=self._api_key_name,
            ssl_verify=self.ssl_verify,
            proxies=self.proxies,
        )
        created = {
            "observable": None,
            "report": None,
            "external_reference": None,
            "labels": [],
        }

        try:
            org_id = self.organization_id
            marking_id = self.marking_definition_id
            observable_id = self._create_observable(created, org_id, marking_id)
            label_ids = self._create_labels(created)
            report_id = self._create_report(created, org_id, marking_id, label_ids)
            external_ref_id = self._create_external_reference(created)
            self._link_report_entities(report_id, observable_id, external_ref_id)

            # Enforce observable contract once all dependent creations have been attempted.
            if observable_id is None:
                raise ValueError("Invalid response from OpenCTI StixCyberObservable.create")

            # Return a JSON-serializable summary instead of raw SDK responses.
            return {
                "observable": {"id": observable_id},
                "report": {"id": report_id},
            }
        except Exception as e:
            try:
                msg = (
                    f"OpenCTI partial state detected after exception: {type(e).__name__}: {e}. "
                    f"Created IDs: observable={created['observable']}, "
                    f"report={created['report']}, "
                    f"external_reference={created['external_reference']}, "
                    f"labels={created['labels']}"
                )
                self.report.errors.append(msg)
            except Exception:
                pass
            raise

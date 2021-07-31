# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

from pycti import OpenCTIApiClient

from api_app import helpers
from ..classes import Connector


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


class OpenCTI(Connector):
    def set_params(self, params):
        self.ssl_verify = params.get("ssl_verify", True)
        self.tlp = params.get(
            "tlp", {"type": "white", "color": "#FFFFFF", "x_opencti_order": 0}
        )
        self.proxies = params.get("proxies", {})
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def get_observable_type(self):
        if self._job.is_sample:
            type = INTELOWL_OPENCTI_TYPE_MAP["file"]
        elif self._job.observable_classification == "hash":
            matched_hash_type = helpers.get_hash_type(self._job.observable_name)
            if matched_hash_type in [
                "md5",
                "sha-1",
                "sha-256",
            ]:  # sha-512 not supported
                type = INTELOWL_OPENCTI_TYPE_MAP["file"]
            else:
                type = INTELOWL_OPENCTI_TYPE_MAP["generic"]  # text
        elif self._job.observable_classification == "ip":
            ip_version = helpers.get_ip_version(self._job.observable_name)
            if ip_version == 4 or ip_version == 6:
                type = INTELOWL_OPENCTI_TYPE_MAP["ip"][f"v{ip_version}"]  # v4/v6
            else:
                type = INTELOWL_OPENCTI_TYPE_MAP["generic"]  # text
        else:
            type = INTELOWL_OPENCTI_TYPE_MAP[self._job.observable_classification]

        return type

    def create_observable(self):
        observable_data = {"type": self.get_observable_type()}
        if self._job.is_sample:
            observable_data["name"] = self._job.file_name
            observable_data["hashes"] = helpers.generate_hashes(self.job_id)
        elif (
            self._job.observable_classification == "hash"
            and observable_data["type"] == "file"
        ):
            # add hash instead of value
            matched_type = helpers.get_hash_type(self._job.observable_name)
            observable_data["hashes"] = {matched_type: self._job.observable_name}
        else:
            observable_data["value"] = self._job.observable_name

        observable = self.opencti_api_client.stix_cyber_observable.create(
            observableData=observable_data,
            createdBy=self.organization["id"],
            objectMarking=self.marking_definition["id"],
        )
        return observable

    def run(self):
        # set up client
        self.opencti_api_client = OpenCTIApiClient(
            url=self.__url_name,
            token=self.__api_key,
            ssl_verify=self.ssl_verify,
            proxies=self.proxies,
        )

        # Create author (if it doesn't exist)
        self.organization = self.opencti_api_client.identity.create(
            type="Organization",
            name="IntelOwl",
            description=(
                "Intel Owl is an Open Source Intelligence, or OSINT solution"
                " to get threat intelligence data about a specific file, an IP"
                " or a domain from a single API at scale.[Visit the project on GitHub]"
                "(https://github.com/intelowlproject/IntelOwl/)"
            ),
        )
        # Create the marking definition
        self.marking_definition = self.opencti_api_client.marking_definition.create(
            definition_type="TLP",
            definition="TLP:%s" % self.tlp["type"].upper(),
            x_opencti_color=self.tlp["color"].upper(),
            x_opencti_order=self.tlp["x_opencti_order"],
        )

        # Create the observable
        observable = self.create_observable()

        # Create the report
        report = self.opencti_api_client.report.create(
            name=f"IntelOwl Job-{self.job_id}",
            description=(
                f"This is IntelOwl's analysis report for Job: {self.job_id}."
                f" Analyzers Executed: {self._job.analyzers_to_execute}"
            ),
            published=self._job.received_request_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=["internal-report"],
            createdBy=self.organization["id"],
            objectMarking=self.marking_definition["id"],
            x_opencti_report_status=2,  # Analyzed
        )
        # Create the external reference
        external_reference = self.opencti_api_client.external_reference.create(
            source_name="IntelOwl Analysis",
            description="View analysis report on the IntelOwl instance",
            url=f"{settings.WEB_CLIENT_URL}/pages/scan/result/{self.job_id}",
        )
        # Add the external reference to the report
        self.opencti_api_client.stix_domain_object.add_external_reference(
            id=report["id"], external_reference_id=external_reference["id"]
        )

        # Link Observable and Report
        self.opencti_api_client.report.add_stix_object_or_stix_relationship(
            id=report["id"], stixObjectOrStixRelationshipId=observable["id"]
        )

        return {
            "observable": self.opencti_api_client.stix_cyber_observable.read(
                id=observable["id"]
            ),
            "report": self.opencti_api_client.report.read(id=report["id"]),
        }

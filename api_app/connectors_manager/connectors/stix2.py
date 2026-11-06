import json
import logging
from typing import List, Tuple

import stix2

from api_app.choices import Classification
from api_app.connectors_manager.classes import CTIConnector
from api_app.connectors_manager.exceptions import ConnectorRunException

logger = logging.getLogger(__name__)


class STIX2(CTIConnector):
    """
    STIX 2.1 Bundle Exporter Connector.
    Converts completed IntelOwl Jobs into standardized OASIS STIX 2.1 JSON bundles.
    """

    def health_check(self, user=None) -> Tuple[bool, str]:
        """STIX2 generation is a local serialization, always healthy."""
        return True, "STIX 2.1 generator ready"

    def _generate_sco(self) -> stix2.base._STIXBase:
        """Generate the Cyber Observable Object (SCO) based on classification."""
        if self.classification == Classification.IP:
            if self.ip_version == 6:
                return stix2.IPv6Address(value=self.observable_value)
            return stix2.IPv4Address(value=self.observable_value)

        elif self.classification == Classification.DOMAIN:
            return stix2.DomainName(value=self.observable_value)

        elif self.classification == Classification.URL:
            return stix2.URL(value=self.observable_value)

        elif self.classification == Classification.HASH and self.hash_type:
            hash_key = self.hash_type.upper().replace("-", "")
            return stix2.File(hashes={hash_key: self.observable_value})

        elif self.classification == Classification.FILE:
            return stix2.File(
                name=self.observable_name,
                hashes={"MD5": self.observable_value},
            )

        raise ConnectorRunException(f"Unsupported observable classification: {self.classification}")

    def _generate_pattern(self) -> str:
        """Generate the STIX 2.1 pattern expression for the Indicator."""
        val = self.observable_value
        if self.classification == Classification.IP:
            field = "ipv6-addr:value" if self.ip_version == 6 else "ipv4-addr:value"
            return f"[{field} = '{val}']"
        elif self.classification == Classification.DOMAIN:
            return f"[domain-name:value = '{val}']"
        elif self.classification == Classification.URL:
            return f"[url:value = '{val}']"
        elif self.classification in (Classification.HASH, Classification.FILE):
            hash_key = (self.hash_type or "MD5").upper().replace("-", "")
            return f"[file:hashes.'{hash_key}' = '{val}']"
        return f"[artifact:payload_bin = '{val}']"

    def run(self) -> dict:
        objects: List[stix2.base._STIXBase] = []

        # 1. Create the Observable (SCO)
        try:
            sco = self._generate_sco()
            objects.append(sco)
        except Exception as e:
            logger.warning(f"Could not generate SCO: {e}")

        # 2. Create the Indicator (SDO)
        pattern = self._generate_pattern()
        indicator_types = ["malicious-activity"] if self.evaluation == "malicious" else ["unknown"]

        external_refs = [
            stix2.ExternalReference(
                source_name="IntelOwl",
                url=self.analysis_url,
                description="View analysis on IntelOwl",
            )
        ]

        indicator = stix2.Indicator(
            name=f"IntelOwl-{self.observable_name}",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
            labels=self.tag_labels or ["intelowl"],
            external_references=external_refs,
        )
        objects.append(indicator)

        # 3. If malware family is identified, create Malware SDO + Relationship
        if self.malware_family:
            malware = stix2.Malware(
                name=self.malware_family,
                is_family=True,
                labels=["malware"],
            )
            objects.append(malware)

            # Link indicator -> indicates -> malware
            rel = stix2.Relationship(
                source_ref=indicator.id,
                target_ref=malware.id,
                relationship_type="indicates",
            )
            objects.append(rel)

        # 4. Package everything into a STIX 2.1 Bundle
        bundle = stix2.Bundle(objects=objects)

        # Return as a pure dictionary ready to be saved / exported
        return json.loads(bundle.serialize())

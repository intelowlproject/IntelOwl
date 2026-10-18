# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Phishunt(classes.ObservableAnalyzer):
    """
    Wrapper for Phishunt.io.

    Phishunt provides information about known phishing domains,
    URLs and IP addresses.
    """

    url = "https://phishunt.io/api/v1/domains"
    timeout = 30

    def update(self):
        return True

    def _get_query(self):
        observable = self.observable_name.strip()

        if self.observable_classification == Classification.URL.value:
            parsed = urlparse(
                observable
                if "://" in observable
                else f"https://{observable}"
            )
            hostname = parsed.hostname

            if not hostname:
                raise AnalyzerRunException("Invalid URL observable")

            return hostname.rstrip(".").lower()

        if self.observable_classification == Classification.DOMAIN.value:
            return observable.rstrip(".").lower()

        if self.observable_classification == Classification.IP.value:
            return observable

        raise AnalyzerRunException(
            f"Unsupported observable classification: "
            f"{self.observable_classification}"
        )


    def run(self):
        query = self._get_query()

        params = (
            {"ip": query}
            if self.observable_classification == Classification.IP.value
            else {"q": query}
        )

        try:
            response = requests.get(
                self.url,
                params=params,
                timeout=self.timeout,
            )

            response.raise_for_status()
            data = response.json()

        except (requests.RequestException, ValueError) as exc:
            raise AnalyzerRunException(exc) from exc

        if not isinstance(data, dict):
            raise AnalyzerRunException(
                "Phishunt returned an invalid response"
            )

        results = data.get("results", [])

        if not isinstance(results, list):
            raise AnalyzerRunException(
                "Phishunt response contains invalid results"
            )

        matched_results = []

        for item in results:
            if not isinstance(item, dict):
                continue

            if self.observable_classification == Classification.DOMAIN.value:
                candidate = item.get("domain", "")
                matches = (
                    isinstance(candidate, str)
                    and candidate.rstrip(".").lower() == query
                )

            elif self.observable_classification == Classification.URL.value:
                candidate = item.get("domain", "")
                candidate_url = item.get("url", "")

                result_hostname = (
                    urlparse(
                        candidate_url
                        if isinstance(candidate_url, str)
                        else ""
                    ).hostname
                    or ""
                )

                matches = (
                    isinstance(candidate, str)
                    and candidate.rstrip(".").lower() == query
                ) or result_hostname.rstrip(".").lower() == query

            else:  # IP
                candidate = item.get("ip", "")
                matches = (
                    isinstance(candidate, str)
                    and candidate == query
                )

            if matches:
                matched_results.append(item)

        return {
            "found": bool(matched_results),
            "results": matched_results,
        }

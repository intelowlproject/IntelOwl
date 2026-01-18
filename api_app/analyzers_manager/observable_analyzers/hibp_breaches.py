# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException

from .hibp_utils import BASE_URL, make_hibp_request, normalize_breach_data


class HibpBreaches(ObservableAnalyzer):
    """
    Analyzer for HaveIBeenPwned breaches (emails and domains).
    Supports: email, domain.
    Requires API key (use test key for dev).
    """

    _api_key_name: str

    truncate_response: bool = False
    include_unverified: bool = False

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.observable_classification not in ["email", "domain"]:
            raise AnalyzerRunException(
                "Unsupported observable type "
                f"{self.observable_classification}. "
                "Supported: email, domain."
            )

        api_key = self._api_key_name
        if not api_key:
            raise AnalyzerRunException(
                "API key required for breach checks (email or domain)."
            )

        if self.observable_classification == "email":
            endpoint = f"{BASE_URL}breachedaccount/{self.observable_name}"
            params = {
                "truncateResponse": self.truncate_response,
                "includeUnverified": self.include_unverified,
            }
        else:
            endpoint = f"{BASE_URL}breaches"
            params = {"domain": self.observable_name}

        breaches = make_hibp_request(endpoint, params=params, api_key=api_key)

        normalized_breaches = normalize_breach_data(breaches)
        breach_count = len(normalized_breaches)
        summary = (
            f"{self.observable_classification.capitalize()} found in "
            f"{breach_count} breaches."
            if breach_count > 0
            else "No breaches found."
        )

        return {
            "success": True,
            "breach_count": breach_count,
            "breaches": normalized_breaches,
            "summary": summary,
        }

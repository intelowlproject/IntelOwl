# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

from api_app.analyzers_manager.classes import ObservableAnalyzer

from .hibp_utils import BASE_URL, make_hibp_request, normalize_breach_data

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class HibpBreaches(ObservableAnalyzer):
    """
    Analyzer for HaveIBeenPwned breaches (emails and domains).

    Supports: email, domain.
    Requires API key (use test key
    '00000000000000000000000000000000' for development).

    Note for domains:
    - Uses public /breaches?domain= endpoint
    → shows which breaches affected the domain
    - Does NOT return individual leaked email addresses
    (requires verified domain + paid key)
    """

    _api_key_name: str

    truncate_response: bool = False
    include_unverified: bool = False

    @classmethod
    def update(cls) -> bool:
        """HIBP Breaches analyzer does not require periodic updates."""
        return True

    def run(self):
        observable = self.observable_name.strip()
        classification = self.observable_classification

        if classification == "domain":
            resolved_type = "domain"

        elif classification == "generic" and EMAIL_REGEX.match(observable):
            resolved_type = "email"

        else:
            raise RuntimeError(
                "Unsupported observable. Use a valid domain or email."
            )  # noqa: E501

        api_key = self._api_key_name
        if not api_key:
            raise RuntimeError(
                "API key required for breach checks (email or domain)."
            )  # noqa: E501

        if resolved_type == "email":
            endpoint = f"{BASE_URL}breachedaccount/{observable}"
            params = {
                "truncateResponse": self.truncate_response,
                "includeUnverified": self.include_unverified,
            }
        else:  # domain
            endpoint = f"{BASE_URL}breaches"
            params = {"domain": observable}

        breaches = make_hibp_request(endpoint, params=params, api_key=api_key)

        normalized_breaches = normalize_breach_data(breaches)
        breach_count = len(normalized_breaches)
        summary = (
            f"{resolved_type.capitalize()} found in "
            f"{breach_count} breaches."  # noqa: E501
            if breach_count > 0
            else "No breaches found."
        )

        result = {
            "success": True,
            "breach_count": breach_count,
            "breaches": normalized_breaches,
            "summary": summary,
        }

        # Optional but very useful warning for users
        if self.observable_classification == "domain":
            result["note"] = (
                "Domain search uses the public /breaches?domain= endpoint. "
                "It shows only breach names/dates/counts — "
                "not individual leaked emails. "
                "Full leaked email list requires domain ownership "
                "verification in HIBP dashboard."
            )

        return result

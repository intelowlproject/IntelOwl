# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException

from .hibp_utils import PWNED_PASSWORDS_URL, make_hibp_request


class HibpPasswords(ObservableAnalyzer):
    """
    Analyzer for HaveIBeenPwned pwned passwords (k-anonymity).
    Supports: generic (password string).
    No API key required.
    Uses privacy-preserving k-anonymity
    (only first 5 chars of SHA-1 hash are sent).
    """

    @classmethod
    def update(cls) -> bool:
        """HIBP Passwords analyzer does not require periodic updates."""
        return True

    def run(self):
        if self.observable_classification != "generic":
            raise AnalyzerRunException(
                "Unsupported observable type "
                f"{self.observable_classification!r}. "
                "Supported: generic (password)."
            )

        password = self.observable_name
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        endpoint = f"{PWNED_PASSWORDS_URL}{prefix}"
        response_text = make_hibp_request(endpoint)

        hashes = response_text.splitlines() if response_text else []

        exposure_count = 0
        for line in hashes:
            if ":" in line:
                hash_suffix, count = line.split(":", 1)
                if hash_suffix == suffix:
                    exposure_count = int(count)
                    break

        summary = (
            f"Password exposed {exposure_count} times in breaches."
            if exposure_count > 0
            else "Password not found in known breaches."
        )

        return {
            "success": True,
            "exposure_count": exposure_count,
            "summary": summary,
        }

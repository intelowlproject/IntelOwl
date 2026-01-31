# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from requests.exceptions import RequestException

# Constants
BASE_URL = "https://haveibeenpwned.com/api/v3/"
PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "IntelOwl-HIBP-Analyzer"


def get_headers(api_key: str = None) -> dict:
    """
    Build standard headers for HIBP requests.
    :param api_key: Optional API key for authenticated endpoints.
    """
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["hibp-api-key"] = api_key
    return headers


def make_hibp_request(
    url: str,
    params: dict = None,
    api_key: str = None,
    timeout: int = 10,
) -> dict | list | str:
    """
    Make a GET request to HIBP API and handle common responses.
    :param url: Full endpoint URL.
    :param params: Query parameters.
    :param api_key: Optional API key.
    :param timeout: Request timeout in seconds.
    :return: Parsed JSON or text response.
    :raises AnalyzerRunException: On errors with details.
    """
    try:
        response = requests.get(
            url,
            params=params or {},
            headers=get_headers(api_key),
            timeout=timeout,
            verify=True,  # Enforce SSL verification
        )

        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return response.json()
            else:
                return response.text
        elif response.status_code == 404:
            # No breaches found - treat as success with empty result
            return [] if "json" in url else ""
        elif response.status_code == 403:
            raise RuntimeError("Forbidden: Check API key or User-Agent.")  # noqa: E501
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise RuntimeError(f"Rate limit hit. Retry after {retry_after} seconds.")  # noqa: E501
        else:
            response.raise_for_status()

    except RequestException as e:
        raise RuntimeError(f"Request failed: {str(e)}")


def normalize_breach_data(breaches: list) -> list:
    """
    Normalize breach response into a consistent structure.
    :param breaches: Raw list from HIBP.
    :return: List of dicts with key fields.
    """
    normalized = []
    for breach in breaches:
        normalized.append(
            {
                "name": breach.get("Name"),
                "breach_date": breach.get("BreachDate"),
                "pwn_count": breach.get("PwnCount"),
                "data_classes": breach.get("DataClasses", []),
                "description": breach.get("Description", ""),
            }
        )
    return normalized

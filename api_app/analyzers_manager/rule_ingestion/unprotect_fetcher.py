# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# standard library
import logging

# third-party
import requests

logger = logging.getLogger(__name__)

UNPROTECT_API_URL = "https://unprotect.it/api/detection_rules/"


def fetch_detection_rules():
    """
    Fetch detection rules from unprotect.it API.
    Returns a list of rule objects (raw JSON).
    """
    try:
        response = requests.get(UNPROTECT_API_URL, timeout=15)
        response.raise_for_status()

        data = response.json()
        rules = data.get("results", [])

        logger.info("Fetched %d rules from unprotect.it", len(rules))
        return rules
    except requests.RequestException as e:
        logger.error("Failed to fetch rules from unprotect.it: %s", e)
        return []

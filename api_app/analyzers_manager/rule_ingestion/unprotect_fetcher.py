import requests
import logging 

logger = logging.getLogger(__name__)

UNPROTECT_API_URL = "https://unprotect.it/api/detection_rules/"

def fetch_detection_rules():
    """
   Fetch detection rules from unprotect.it API.
   Returns a list of rule objects(raw JSON).

    """
    try:
        response = requests.get(UNPROTECT_API_URL, timeout=15)
        response.raise_for_status()

        data = response.json()
        rules = data.get("results", [])

        logger.info(f"Fetched {len(rules)} rules from unprotect.it")
        return rules
    except Exception as e:
        logger.error(f"Failed to fetch rules from unprotect.it: {e}")
        return []
    
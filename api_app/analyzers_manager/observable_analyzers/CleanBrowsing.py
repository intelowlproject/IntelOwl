import base64
import requests

from django.utils.translation import gettext_lazy as _
from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

class CleanBrowsing(ObservableAnalyzer):
    typename = "CleanBrowsing"
    observable_classification = "domain"
    
    # BEST PRACTICE: Define static URLs as constants here
    URL_FAMILY = "https://doh.cleanbrowsing.org/doh/family-filter/"
    URL_ADULT = "https://doh.cleanbrowsing.org/doh/adult-filter/"
    URL_SECURITY = "https://doh.cleanbrowsing.org/doh/security-filter/"
    
    configuration_options = {
        "filter_type": {
            "type": "string",
            "default": "family",
            "choices": ["family", "adult", "security"],
            "description": _("Choose 'family' (strictest), 'adult' (blocks porn), or 'security' (malware only)."),
        }
    }

    @classmethod
    def update(cls):
        return False

    def run(self):
        target_domain = self.observable_name
        filter_type = getattr(self, "filter_type", "family")
        
        # Cleaner logic using the constants
        if filter_type == "security":
            url = self.URL_SECURITY
        elif filter_type == "adult":
            url = self.URL_ADULT
        else:
            url = self.URL_FAMILY

        binary_dns = self._create_dns_query(target_domain)
        # Remove the padding '=' as per DNS-over-HTTPS spec
        b64_payload = base64.urlsafe_b64encode(binary_dns).decode("utf-8").rstrip("=")

        try:
            headers = {"Accept": "application/dns-message"}
            params = {"dns": b64_payload}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()

            return {
                "filter_used": filter_type,
                "status_code": response.status_code,
                "is_blocked": self._check_if_blocked(response.content),
                "raw_response_length": len(response.content)
            }

        except requests.exceptions.RequestException as e:
            raise AnalyzerRunException(f"Connection to CleanBrowsing failed: {e}")

    @staticmethod
    def _create_dns_query(domain):
        # ... (Your existing static method code is fine) ...
        packet = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        parts = domain.split('.')
        for part in parts:
            packet += bytes([len(part)]) + part.encode('utf-8')
        packet += b'\x00'
        packet += b'\x00\x01\x00\x01'
        return packet

    @staticmethod
    def _check_if_blocked(binary_response):
        # ... (Your existing static method code is fine) ...
        if not binary_response or len(binary_response) < 12:
            return False 
        rcode = binary_response[3] & 0x0F
        return rcode == 3
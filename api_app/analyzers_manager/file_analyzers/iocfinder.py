import logging

from ioc_finder import find_iocs

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class IocFinder(FileAnalyzer):
    parse_domain_from_url: bool = True
    parse_from_url_path: bool = True
    parse_domain_from_email_address: bool = True
    parse_address_from_cidr: bool = True
    parse_domain_name_from_xmpp_address: bool = True
    parse_urls_without_scheme: bool = True
    parse_imphashes: bool = True
    parse_authentihashes: bool = True

    def update(self):
        pass

    def run(self):
        logger.info(f"Running IOC Finder on {self.filepath} for {self.md5}")
        binary_data = self.read_file_bytes()
        text_data = binary_data.decode("utf-8")

        iocs = find_iocs(
            text_data,
            parse_domain_from_url=self.parse_domain_from_url,
            parse_from_url_path=self.parse_from_url_path,
            parse_domain_from_email_address=self.parse_domain_from_email_address,
            parse_address_from_cidr=self.parse_address_from_cidr,
            parse_domain_name_from_xmpp_address=self.parse_domain_name_from_xmpp_address,  # noqa: E501
            parse_urls_without_scheme=self.parse_urls_without_scheme,
            parse_imphashes=self.parse_imphashes,
            parse_authentihashes=self.parse_authentihashes,
        )

        return iocs

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import iocextract as i

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class IocEctract(FileAnalyzer):
    refang: bool = False
    defang: bool = False
    strip: bool = False
    extract_urls: bool = False
    extract_ips: bool = False
    extract_emails: bool = False
    extract_hashes: bool = False
    extract_yara_rules: bool = False
    extract_telephone_nums: bool = False
    extract_iocs: bool = True

    def update(self):
        pass

    def run(self):
        binary_data = self.read_file_bytes()
        text_data = binary_data.decode("utf-8")
        if self.extract_iocs:
            report = list(
                i.extract_iocs(text_data, refang=self.refang, strip=self.strip)
            )
        else:
            report = {}

            if self.extract_urls:
                report["urls"] = list(
                    i.extract_urls(
                        text_data,
                        refang=self.refang,
                        strip=self.strip,
                        defang=self.defang,
                    )
                )
            if self.extract_ips:
                report["ips"] = list(i.extract_ips(text_data, refang=self.refang))
            if self.extract_emails:
                report["emails"] = list(i.extract_emails(text_data, refang=self.refang))
            if self.extract_hashes:
                report["hashes"] = list(i.extract_hashes(text_data))
            if self.extract_yara_rules:
                report["yara_rules"] = list(i.extract_yara_rules(text_data))
            if self.extract_telephone_nums:
                report["telephone_nums"] = list(i.extract_telephone_nums(text_data))
        return report

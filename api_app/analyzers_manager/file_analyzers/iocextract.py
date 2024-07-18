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
            return {
                "all_iocs": list(
                    i.extract_iocs(text_data, refang=self.refang, strip=self.strip)
                )
            }

        extraction_methods = {
            "urls": (
                self.extract_urls,
                lambda: i.extract_urls(
                    text_data, refang=self.refang, strip=self.strip, defang=self.defang
                ),
            ),
            "ips": (
                self.extract_ips,
                lambda: i.extract_ips(text_data, refang=self.refang),
            ),
            "emails": (
                self.extract_emails,
                lambda: i.extract_emails(text_data, refang=self.refang),
            ),
            "hashes": (self.extract_hashes, lambda: i.extract_hashes(text_data)),
            "yara_rules": (
                self.extract_yara_rules,
                lambda: i.extract_yara_rules(text_data),
            ),
            "telephone_nums": (
                self.extract_telephone_nums,
                lambda: i.extract_telephone_nums(text_data),
            ),
        }

        return {
            key: list(method())
            for key, (flag, method) in extraction_methods.items()
            if flag
        }

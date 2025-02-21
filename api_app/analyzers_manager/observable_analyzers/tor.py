# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import re

from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import AnalyzerSourceFile, TorExitAddress

logger = logging.getLogger(__name__)

db_name = "tor_exit_addresses.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Tor(classes.ObservableAnalyzer):
    file_name = "tor_exit_addresses.txt"
    url = "https://check.torproject.org/exit-addresses"
    regex_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    def _do_create_data_model(self) -> bool:
        return super()._do_create_data_model() and self.report.report["found"]

    def run(self):
        result = {"found": False}

        tor_exit_address = TorExitAddress.objects.filter(
            ip=self.observable_name
        ).exists()
        if tor_exit_address:
            result["found"] = True

        return result

    @classmethod
    def update(cls):
        request_data = {"url": cls.url}
        return cls.update_internal_data(
            request_data,
            cls.file_name,
        )

    @classmethod
    def update_support_model(cls, file_name):
        source_file = AnalyzerSourceFile.objects.filter(
            file_name=file_name, python_module=cls.python_module
        ).first()

        records = []
        for line in source_file.file.readlines():
            line = line.decode()
            ip_address_found = re.search(cls.regex_ip, line)
            if ip_address_found:
                ip_address_found = ip_address_found.group()

                records.append({"ip": ip_address_found})

        TorExitAddress.generate(records)

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)

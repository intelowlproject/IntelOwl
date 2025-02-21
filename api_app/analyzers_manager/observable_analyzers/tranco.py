# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from io import BytesIO
from urllib.parse import urlparse
from zipfile import ZipFile

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import AnalyzerSourceFile, TrancoRecord

logger = logging.getLogger(__name__)


class Tranco(classes.ObservableAnalyzer):
    url: str = "https://tranco-list.s3.amazonaws.com/top-1m.csv.zip"

    @classmethod
    def update(cls) -> bool:
        request_data = {
            "url": cls.url,
        }
        return cls.update_internal_data(
            request_data,
            "tranco_ranks.zip",
        )

    @classmethod
    def update_support_model(cls, file_name):
        source_file = AnalyzerSourceFile.objects.filter(
            file_name=file_name, python_module=cls.python_module
        ).first()

        records = []
        with ZipFile(BytesIO(source_file.file.read())) as thezip:
            with thezip.open("top-1m.csv") as f:
                for i, line in enumerate(f.readlines()):
                    rank, domain = line.decode().strip().split(",")
                    records.append(
                        {
                            "rank": rank,
                            "domain": domain,
                        }
                    )
        TrancoRecord.generate(records)

    def run(self):
        result = {"found": False}

        domain_extracted = urlparse(self.observable_name).hostname
        if domain_extracted:
            domain_to_evaluate = domain_extracted
        else:
            domain_to_evaluate = self.observable_name

        if domain_to_evaluate.startswith("www."):
            domain_to_evaluate = domain_to_evaluate[4:]

        records = (
            TrancoRecord.objects.filter(domain=domain_to_evaluate)
            .order_by("-retrieved_date")
            .values()
        )

        for rec in records:
            rec["last_update"] = rec["last_update"].strftime("%Y-%m-%d %H:%M:%S")
            rec["retrieved_date"] = rec["retrieved_date"].strftime("%Y-%m-%d %H:%M:%S")

        if records:
            result["found"] = True
            result["ranks"] = list(records)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)

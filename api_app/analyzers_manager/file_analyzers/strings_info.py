# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from json import dumps as json_dumps

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.models import MimeTypes
from api_app.choices import Classification


class StringsInfo(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "StringsInfo"
    url: str = "http://malware_tools_analyzers:4002/stringsifter"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    max_number_of_strings: int
    max_characters_for_string: int
    # If set, this module will use Machine Learning feature
    # CARE!! ranked_strings could be cpu/ram intensive and very slow
    rank_strings: int

    def update(self) -> bool:
        pass

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = ["flarestrings", f"@{fname}"]
        req_data = {
            "args": args,
            "timeout": self.timeout,
        }
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files)
        exceed_max_strings = len(result) > self.max_number_of_strings
        if exceed_max_strings:
            result = list(result[: self.max_number_of_strings])
        if self.rank_strings:
            args = [
                "rank_strings",
                "--limit",
                str(self.max_number_of_strings),
                "--strings",
                json_dumps(result),
            ]
            req_data = {"args": args, "timeout": self.timeout}
            result = self._docker_run(req_data)
        result = {
            "data": [row[: self.max_characters_for_string] for row in result],
            "exceeded_max_number_of_strings": exceed_max_strings,
            "uris": [],
        }

        if self.file_mimetype in [
            MimeTypes.JAVASCRIPT1.value,
            MimeTypes.JAVASCRIPT2.value,
            MimeTypes.JAVASCRIPT3.value,
            MimeTypes.VB_SCRIPT.value,
            MimeTypes.ONE_NOTE.value,
            MimeTypes.PDF.value,
            MimeTypes.HTML.value,
            MimeTypes.EXCEL1.value,
            MimeTypes.EXCEL2.value,
            MimeTypes.EXCEL_MACRO1.value,
            MimeTypes.EXCEL_MACRO2.value,
            MimeTypes.DOC.value,
            MimeTypes.WORD1.value,
            MimeTypes.WORD2.value,
            MimeTypes.XML1.value,
            MimeTypes.XML2.value,
            MimeTypes.POWERPOINT.value,
            MimeTypes.OFFICE.value,
            MimeTypes.EML.value,
            MimeTypes.JSON.value,
        ]:
            import re

            for d in result["data"]:
                if Classification.calculate_observable(d) == Classification.URL:
                    extracted_urls = re.findall(
                        r"[a-z]{1,5}://[a-z\d-]{1,200}"
                        r"(?:\.[a-zA-Z\d\u2044\u2215!#$&(-;=?-\[\]_~]{1,200})+"
                        r"(?::\d{2,6})?"
                        r"(?:/[a-zA-Z\d\u2044\u2215!#$&(-;=?-\[\]_~]{1,200})*"
                        r"(?:\.\w+)?",
                        d,
                    )
                    for u in extracted_urls:
                        result["uris"].append(u)
            result["uris"] = list(set(result["uris"]))

        return result

    # disable mockup connections for this class
    @classmethod
    def _monkeypatch(cls, patches: list = None) -> None: ...  # noqa: E704

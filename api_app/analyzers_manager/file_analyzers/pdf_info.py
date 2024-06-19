# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
from typing import Any, List

import pdfreader
import peepdf
import pikepdf
from pdfid import pdfid

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class PDFInfo(FileAnalyzer):
    @staticmethod
    def flatten(list_of_lists: List[List[Any]]) -> List[Any]:
        return [item for sublist in list_of_lists for item in sublist]

    def run(self):
        self.results = {"peepdf": {}, "pdfid": {}, "pdfreader": {}, "uris": []}

        # the analysis fails only when BOTH fails
        peepdf_success = self.__peepdf_analysis()
        pdfid_success = self.__pdfid_analysis()
        pdfreader_success = self.__pdfreader_analysis()

        if not pdfreader_success and not (pdfid_success and peepdf_success):
            raise AnalyzerRunException("all readers failed")

        # pivot uris in the pdf only if we have one page
        if self.results["pdfreader"]["pages"] == 1:
            uris = []
            for s in self.results["peepdf"]["stats"]:
                uris.extend(s["uris"])
            uris.extend(self.results["pdfreader"]["uris"])
            logger.info(f"{uris=}")
            uris = list(set(uris))  # removing duplicates
            if uris:
                self.results["uris"] = uris

        return self.results

    def __pdfreader_analysis(self):
        self.results["pdfreader"]["uris"] = []
        success = True
        parser_exception = False

        # pre-processing pdf file
        doc = pikepdf.Pdf.open(self.filepath)
        doc.save(
            os.path.join(self.filepath + "_stream_disabled.pdf"),
            fix_metadata_version=True,
            object_stream_mode=pikepdf.ObjectStreamMode.disable,
        )

        with open(os.path.join(self.filepath + "_stream_disabled.pdf"), "rb") as fd:
            try:
                doc = pdfreader.PDFDocument(fd)
            except pdfreader.exceptions.ParserException:
                parser_exception = True
            else:
                self.results["pdfreader"]["pages"] = doc.root["Pages"]["Count"]
                for page in doc.root["Pages"]["Kids"]:
                    for annot in page["Annots"]:
                        if "A" in annot:
                            if "URI" in annot["A"]:
                                self.results["pdfreader"]["uris"].append(
                                    annot["A"]["URI"].decode("utf8")
                                )

        if parser_exception and len(self.results["uris"]) == 0:
            success = False

        os.unlink(os.path.join(self.filepath + "_stream_disabled.pdf"))

        return success

    def __peepdf_analysis(self):
        success = False
        peepdf_analysis = {}
        try:
            pdf_parser = peepdf.PDFCore.PDFParser()
            ret, pdf = pdf_parser.parse(self.filepath, True)
            if ret:
                peepdf_analysis["status_code"] = ret
            else:
                stats = pdf.getStats()
                peepdf_analysis["stats"] = []
                for version in stats.get("Versions", []):
                    version_dict = {
                        "events": version.get("Events", {}),
                        "actions": version.get("Actions", {}),
                        "urls": self.flatten(pdf.getURLs()),
                        "uris": self.flatten(pdf.getURIs()),
                        "elements": version.get("Elements", {}),
                        "vulns": version.get("Vulns", []),
                        "objects_with_js_code": version.get("Objects with JS code", []),
                    }
                    peepdf_analysis["stats"].append(version_dict)

            self.results["peepdf"] = peepdf_analysis
        except TypeError as e:
            # rc4Key = rc4Key[:keyLength]
            # TypeError: slice indices must be integers or None or
            # have an __index__ method
            self.results["peepdf"]["error"] = str(e)
        except UnboundLocalError as e:
            logger.info(e, stack_info=True)
            self.results["peepdf"]["error"] = str(e)
        except Exception as e:
            logger.exception(e)
            self.results["peepdf"]["error"] = str(e)
        else:
            success = True
        return success

    def __pdfid_analysis(self):
        success = False
        try:
            options = pdfid.get_fake_options()
            options.json = True
            list_of_dict = pdfid.PDFiDMain([self.filepath], options)
            self.results["pdfid"] = list_of_dict
        except Exception as e:
            logger.exception(e)
            self.results["pdfid"]["error"] = str(e)
        else:
            success = True
        return success

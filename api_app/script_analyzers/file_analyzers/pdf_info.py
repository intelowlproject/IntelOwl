import logging
import peepdf
from pdfid import pdfid

from api_app.script_analyzers.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class PDFInfo(FileAnalyzer):
    def run(self):
        self.results = {"peepdf": {}, "pdfid": {}}
        # the analysis fails only when BOTH fails
        peepdf_success = self.__peepdf_analysis()
        pdfid_success = self.__pdfid_analysis()
        if not peepdf_success and not pdfid_success:
            raise AnalyzerRunException("both peepdf and pdfid failed")
        return self.results

    def __peepdf_analysis(self):
        success = False
        peepdf_analysis = []
        try:
            pdf_parser = peepdf.PDFCore.PDFParser()
            ret, pdf = pdf_parser.parse(self.filepath, True)
            if ret:
                peepdf_analysis["status_code"] = ret
            else:
                stats = pdf.getStats()
                for version in stats.get("Versions", []):
                    version_dict = {
                        "events": version.get("Events", {}),
                        "actions": version.get("Actions", {}),
                        "urls": version.get("URLs", []),
                        "uris": version.get("URIs", []),
                        "elements": version.get("Elements", {}),
                        "vulns": version.get("Vulns", []),
                        "objects_with_js_code": version.get("Objects with JS code", []),
                    }
                    peepdf_analysis.append(version_dict)

            self.results["peepdf"] = peepdf_analysis
        except Exception as e:
            logger.exception(e)
            self.results["peepdf"]["error"] = e
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
            self.results["pdfid"]["error"] = e
        else:
            success = True
        return success

import peepdf

from api_app.script_analyzers.classes import FileAnalyzer


class PDFInfo(FileAnalyzer):
    def run(self):
        results = {}
        peepdf_analysis = []
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

        results["peepdf"] = peepdf_analysis

        return results

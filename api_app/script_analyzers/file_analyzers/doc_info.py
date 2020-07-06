import traceback
import logging

from oletools import mraptor
from oletools.olevba import VBA_Parser

from api_app.script_analyzers.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class DocInfo(FileAnalyzer):
    def run(self):
        results = {}
        # olevba
        olevba_results = {}
        try:
            vbaparser = VBA_Parser(self.filepath)

            olevba_results["macro_found"] = (
                True if vbaparser.detect_vba_macros() else False
            )

            if olevba_results["macro_found"]:
                macro_data = []
                for (
                    v_filename,
                    stream_path,
                    vba_filename,
                    vba_code,
                ) in vbaparser.extract_macros():
                    extracted_macro = {
                        "filename": v_filename,
                        "ole_stream": stream_path,
                        "vba_filename": vba_filename,
                        "vba_code": vba_code,
                    }
                    macro_data.append(extracted_macro)
                olevba_results["macro_data"] = macro_data

                # example output
                """
                {'description': 'Runs when the Word document is opened',
                 'keyword': 'AutoOpen',
                 'type': 'AutoExec'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'Shell',
                 'type': 'Suspicious'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'WScript.Shell',
                 'type': 'Suspicious'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'Run',
                 'type': 'Suspicious'},
                {'description': 'May run PowerShell commands',
                 'keyword': 'powershell',
                 'type': 'Suspicious'},
                {'description': '9BA55BE5', 'keyword': 'xxx', 'type': 'Hex String'},
                 """
                analyzer_results = vbaparser.analyze_macros(show_decoded_strings=True)
                # it gives None if it does not find anything
                if analyzer_results:
                    analyze_macro_results = []
                    for kw_type, keyword, description in analyzer_results:
                        if kw_type != "Hex String":
                            analyze_macro_result = {
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description,
                            }
                            analyze_macro_results.append(analyze_macro_result)
                    olevba_results["analyze_macro"] = analyze_macro_results

                olevba_results["reveal"] = vbaparser.reveal()

            vbaparser.close()

        except Exception as e:
            traceback.print_exc()
            error_message = f"job_id {self.job_id} vba parser failed. Error: {e}"
            logger.exception(error_message)
            self.report["errors"].append(error_message)

        results["olevba"] = olevba_results

        # mraptor
        macro_raptor = mraptor.MacroRaptor(olevba_results.get("reveal", None))
        if macro_raptor:
            macro_raptor.scan()
            results["mraptor"] = "suspicious" if macro_raptor.suspicious else "ok"

        return results

from oletools.rtfobj import RtfObjParser

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer


class RTFInfo(FileAnalyzer):
    def run(self):
        results = {}

        rtfobj_results = {}
        binary = get_binary(self.job_id)
        rtfp = RtfObjParser(binary)
        rtfp.parse()
        rtfobj_results["ole_objects"] = []
        for rtfobj in rtfp.objects:
            if rtfobj.is_ole:
                class_name = rtfobj.class_name.decode()
                ole_dict = {
                    "format_id": rtfobj.format_id,
                    "class_name": class_name,
                    "ole_datasize": rtfobj.oledata_size,
                }
                if rtfobj.is_package:
                    ole_dict["is_package"] = True
                    ole_dict["filename"] = rtfobj.filename
                    ole_dict["src_path"] = rtfobj.src_path
                    ole_dict["temp_path"] = rtfobj.temp_path
                    ole_dict["olepkgdata_md5"] = rtfobj.olepkgdata_md5
                else:
                    ole_dict["ole_md5"] = rtfobj.oledata_md5
                if rtfobj.clsid:
                    ole_dict["clsid_desc"] = rtfobj.clsid_desc
                    ole_dict["clsid_id"] = rtfobj.clsid
                rtfobj_results["ole_objects"].append(ole_dict)
                # http://www.kb.cert.org/vuls/id/921560
                if class_name == "OLE2Link":
                    rtfobj_results["exploit_ole2link_vuln"] = True
                # https://www.kb.cert.org/vuls/id/421280/
                elif class_name.lower() == "equation.3":
                    rtfobj_results["exploit_equation_editor"] = True

        results["rtfobj"] = rtfobj_results

        return results

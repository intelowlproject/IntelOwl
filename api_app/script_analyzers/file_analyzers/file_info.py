import hashlib
import pydeep
import magic
import pyexifinfo

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer


class FileInfo(FileAnalyzer):
    def run(self):
        results = {}
        results["magic"] = magic.from_file(self.filepath)
        results["mimetype"] = magic.from_file(self.filepath, mime=True)
        results["filetype"] = pyexifinfo.fileType(self.filepath)

        exif_report = pyexifinfo.get_json(self.filepath)
        if exif_report:
            exif_report_cleaned = {
                key: value
                for key, value in exif_report[0].items()
                if not (key.startswith("File") or key.startswith("SourceFile"))
            }
            results["exiftool"] = exif_report_cleaned

        binary = get_binary(self.job_id)
        results["md5"] = hashlib.md5(binary).hexdigest()
        results["sha1"] = hashlib.sha1(binary).hexdigest()
        results["sha256"] = hashlib.sha256(binary).hexdigest()
        results["ssdeep"] = pydeep.hash_file(self.filepath).decode()

        return results

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import hashlib
import pydeep
import magic
from exiftool import ExifTool

from api_app.helpers import get_binary
from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class FileInfo(FileAnalyzer):
    def set_config(self, additional_config_params):
        # check repo_downloader.sh file
        self.exiftool_path = (
            "/opt/deploy/exiftool_download/Image-ExifTool-12.26/exiftool"
        )

    def run(self):
        results = {}
        results["magic"] = magic.from_file(self.filepath)
        results["mimetype"] = magic.from_file(self.filepath, mime=True)

        binary = get_binary(self.job_id)
        results["md5"] = hashlib.md5(binary).hexdigest()
        results["sha1"] = hashlib.sha1(binary).hexdigest()
        results["sha256"] = hashlib.sha256(binary).hexdigest()
        results["ssdeep"] = pydeep.hash_file(self.filepath).decode()

        try:
            with ExifTool(self.exiftool_path) as et:
                exif_report = et.execute_json(self.filepath)
                if exif_report:
                    exif_single_report = exif_report[0]
                    exif_report_cleaned = {
                        key: value
                        for key, value in exif_single_report.items()
                        if not (key.startswith("File") or key.startswith("SourceFile"))
                    }
                    # compatibility with the previous version of this analyzer
                    results["filetype"] = exif_single_report.get("File:FileType", "")
                    results["exiftool"] = exif_report_cleaned
        except Exception as e:
            logger.exception(e)

        return results

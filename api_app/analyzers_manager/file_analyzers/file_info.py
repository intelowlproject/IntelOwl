# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging

import magic
import pydeep
from exiftool import ExifTool

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class FileInfo(FileAnalyzer):
    def set_params(self, params):
        # check repo_downloader.sh file
        exiftool_download_path = "/opt/deploy/exiftool_download"
        with open(f"{exiftool_download_path}/exiftool_version.txt", "r") as f:
            version = f.read().strip()
        self.exiftool_path = (
            f"{exiftool_download_path}/Image-ExifTool-{version}/exiftool"
        )

    def run(self):
        results = {}
        results["magic"] = magic.from_file(self.filepath)
        results["mimetype"] = magic.from_file(self.filepath, mime=True)

        binary = self.read_file_bytes()
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

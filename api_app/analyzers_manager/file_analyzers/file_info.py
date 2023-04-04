# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import magic
import pydeep
import tlsh
from django.conf import settings
from exiftool import ExifTool

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.helpers import calculate_md5, calculate_sha1, calculate_sha256

logger = logging.getLogger(__name__)


class FileInfo(FileAnalyzer):
    EXIF_TOOL_PATH = settings.BASE_DIR / "exiftool_download"

    def config(self):
        super().config()
        # check repo_downloader.sh file
        with open(f"{self.EXIF_TOOL_PATH}/exiftool_version.txt", "r") as f:
            version = f.read().strip()
        self.exiftool_path = f"{self.EXIF_TOOL_PATH}/Image-ExifTool-{version}/exiftool"

    def run(self):
        results = {}
        results["magic"] = magic.from_file(self.filepath)
        results["mimetype"] = magic.from_file(self.filepath, mime=True)

        binary = self.read_file_bytes()
        results["md5"] = calculate_md5(binary)
        results["sha1"] = calculate_sha1(binary)
        results["sha256"] = calculate_sha256(binary)
        results["ssdeep"] = pydeep.hash_file(self.filepath).decode()
        results["tlsh"] = tlsh.hash(binary)

        try:
            # check repo_downloader.sh file
            with open(
                f"{self.EXIF_TOOL_PATH}/exiftool_version.txt", "r", encoding="utf-8"
            ) as f:
                version = f.read().strip()
            exiftool_path = f"{self.EXIF_TOOL_PATH}/Image-ExifTool-{version}/exiftool"
            with ExifTool(exiftool_path) as et:
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

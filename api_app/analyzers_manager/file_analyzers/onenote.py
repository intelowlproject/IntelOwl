# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import json
import logging

from pyOneNote.Main import process_onenote_file

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class OneNoteInfo(FileAnalyzer):
    def run(self):
        with open(self.filepath, "rb") as file:
            results = json.loads(process_onenote_file(file, "", "", True))
            results["stored_base64"] = []
            for guid, f in results["files"].items():
                if f["extension"] not in (".png", ".jpg"):
                    results["stored_base64"].append(
                        base64.b64encode(bytes.fromhex(f["content"])).decode("ascii")
                    )
        return results

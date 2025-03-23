# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import subprocess
import json
from typing import Dict

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class FlossPip(FileAnalyzer):
    name: str = "FlossPip"
    description: str = "FLOSS extracts obfuscated strings from executables"
    max_no_of_strings: dict
    rank_strings: dict

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)

    def run(self):
        try:
            # get binary
            binary = self.read_file_bytes()
            # make request data
            fname = str(self.filename).replace("/", "_").replace(" ", "_")
            # From floss v3 there is prompt that can be overcome
            # by using the flag --no static.
            # We can lose static strings considering that we can easily
            # retrieve them with more simple tools
            
            # Create a temporary file to write the binary to
            with open(fname, "wb") as f:
                f.write(binary)
            
            # Run flare-floss command
            args = ["flare-floss", fname, "--json", "--no", "static"]
            
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                raise AnalyzerRunException(f"Floss failed with error: {stderr}")
            
            # Clean up the temporary file
            import os
            os.remove(fname)
            
            # Parse the JSON output
            try:
                result = json.loads(stdout)
            except json.JSONDecodeError:
                raise AnalyzerRunException(
                    f"Failed to parse JSON output from flare-floss. Output: {stdout}"
                )
            
            if not isinstance(result, dict):
                raise AnalyzerRunException(
                    f"Result from floss tool is not a dict but is {type(result)}."
                    f" Full dump: {result}"
                )
            
            result["exceeded_max_number_of_strings"] = {}
            return result
            
        except Exception as e:
            raise AnalyzerRunException(f"Floss failed: {str(e)}") 
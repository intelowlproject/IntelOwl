# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import subprocess
import json
from typing import Dict

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Capa(FileAnalyzer):
    name: str = "Capa"
    description: str = "Capa detects capabilities in executable files"
    shellcode: bool
    arch: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.args = []
        if self.arch != "64":
            self.arch = "32"
        if self.shellcode:
            self.args.append("-f")
            self.args.append("sc" + self.arch)

    def run(self):
        try:
            # get binary
            binary = self.read_file_bytes()
            # create file name
            fname = str(self.filename).replace("/", "_").replace(" ", "_")
            
            # Create a temporary file to write the binary to
            with open(fname, "wb") as f:
                f.write(binary)
            
            # Run capa command
            args = ["capa", fname, *self.args, "--json"]
            
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            stdout, stderr = process.communicate()
            
            # Clean up the temporary file
            import os
            os.remove(fname)
            
            if process.returncode != 0:
                raise AnalyzerRunException(f"Capa failed with error: {stderr}")
            
            # Return the JSON output
            return stdout
            
        except Exception as e:
            raise AnalyzerRunException(f"Capa failed: {str(e)}") 
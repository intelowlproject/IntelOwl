# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import speakeasy
import speakeasy.winenv.arch as e_arch

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class SpeakEasy(FileAnalyzer):

    def set_params(self, params):
        self.raw_offset = params.get("raw_offset", 0x0)
        self.arch = params.get("arch", "x64")
        self.shellcode = params.get("shellcode", False)

    def run(self):
        results = {}
        s = speakeasy.Speakeasy()
        if self.shellcode:
            arch = e_arch.ARCH_AMD64
            if self.arch == 'x86':
                arch = e_arch.ARCH_X86
            sc_addr = s.load_shellcode(self.filepath, arch)
            s.run_shellcode(sc_addr, offset=self.raw_offset or 0)
        else:
            m = s.load_module(self.filepath)
            s.run_module(m)
        results = s.get_report()

        return results

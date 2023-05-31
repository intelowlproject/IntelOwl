# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import speakeasy
import speakeasy.winenv.arch as e_arch

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class SpeakEasy(FileAnalyzer):
    raw_offset: int
    arch: str
    shellcode: bool

    def run(self):
        s = speakeasy.Speakeasy()
        if self.shellcode:
            arch = e_arch.ARCH_AMD64
            if self.arch == "x86":
                arch = e_arch.ARCH_X86
            sc_addr = s.load_shellcode(self.filepath, arch)
            s.run_shellcode(sc_addr, offset=self.raw_offset or 0)
        else:
            m = s.load_module(self.filepath)
            s.run_module(m)
        results = s.get_report()

        return results

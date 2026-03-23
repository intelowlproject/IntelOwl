# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Any, Dict

import machofile

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


def _safe_decode(value: Any) -> str:
    """Helper to safely decode bytes to string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore")
    return str(value)


class MachoInfo(FileAnalyzer):
    """
    Analyzer for Mach-O binary files (macOS/iOS executables).
    Uses the machofile library to parse and extract information.
    """

    @classmethod
    def update(cls) -> bool:
        return False

    def _parse_macho(self):
        """Attempts to parse the file as Single or Universal Mach-O."""
        try:
            macho = machofile.MachO(self.filepath)
            try:
                macho.parse()
            except AttributeError:
                pass
            return macho
        except Exception as e:
            try:
                macho = machofile.UniversalMachO(self.filepath)
                try:
                    macho.parse()
                except AttributeError:
                    pass
                return macho
            except Exception as universal_error:
                raise AnalyzerRunException(
                    f"Failed to parse as both single and universal binary. "
                    f"Single: {e}, Universal: {universal_error}"
                )

    def _extract_basic_info(self, macho, results: Dict[str, Any]):
        """Extract basic information like headers and hashes."""
        results["general_info"] = macho.get_general_info()
        results["header"] = macho.get_macho_header()
        results["hashes"] = macho.get_similarity_hashes()
        results["code_signature"] = macho.code_signature_info
        try:
            results["architectures"] = macho.get_architectures()
        except AttributeError:
            results["architectures"] = []
        results["uuid"] = macho.uuid
        results["entrypoint"] = macho.entry_point
        results["version_info"] = macho.version_info

    def _extract_lists(self, macho, results: Dict[str, Any]):
        """Extract list-based structures like load commands and segments."""
        is_universal = isinstance(macho, machofile.UniversalMachO)

        def get_macho_lists(m):
            return {
                "load_commands": [str(lc) for lc in m.load_commands],
                "segments": [str(s) for s in m.segments],
                "dylib_names": [_safe_decode(d) for d in m.dylib_names],
            }

        if is_universal:
            for k in ["load_commands", "segments", "dylib_names"]:
                results[k] = {}
            for arch, m in macho.architectures.items():
                sub_lists = get_macho_lists(m)
                for k, v in sub_lists.items():
                    results[k][arch] = v
        else:
            results.update(get_macho_lists(macho))

    def _extract_symbols(self, macho, results: Dict[str, Any]):
        """Extract imported and exported symbols."""
        results["imports"] = macho.get_imported_functions()
        results["exports"] = macho.get_exported_symbols()

    def run(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {}

        try:
            macho = self._parse_macho()
            self._extract_basic_info(macho, results)
            self._extract_lists(macho, results)
            self._extract_symbols(macho, results)

        except Exception as e:
            error_msg = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                f"md5:{self.md5} filename:{self.filename} "
                f"MachoInfo parsing error: {e}"
            )
            logger.error(error_msg, exc_info=True)
            self.report.errors.append(error_msg)
            raise AnalyzerRunException(error_msg)

        return results

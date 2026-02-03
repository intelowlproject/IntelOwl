# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Any, Dict

try:
    import machofile
except ImportError:
    machofile = None

from api_app.analyzers_manager.classes import FileAnalyzer

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

    API Validation Strategy:
    This analyzer uses defensive programming with hasattr() checks because:
    - The machofile library API varies between single-arch and Universal (FAT) binaries
    - Different Mach-O file types may expose different methods/properties
    - The behavior is validated through tests and internal documentation

    Library reference: https://github.com/pstirparo/machofile
    """

    @classmethod
    def update(cls) -> bool:
        return False


    def _parse_macho(self):
        """Attempts to parse the file as Single or Universal Mach-O."""
        try:
            macho = machofile.MachO(self.filepath)
            if hasattr(macho, "parse"):
                macho.parse()
            return macho
        except Exception as e:
            try:
                macho = machofile.UniversalMachO(self.filepath)
                if hasattr(macho, "parse"):
                    macho.parse()
                return macho
            except Exception as universal_error:
                error_msg = (
                    f"Failed to parse as both single and universal binary. "
                    f"Single: {e}, Universal: {universal_error}"
                )
                logger.warning(
                    f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                    f"md5:{self.md5} {error_msg}"
                )
                raise Exception(error_msg)

    def _extract_basic_info(self, macho, results: Dict[str, Any]):
        """Extracts basic info like header, architectures, uuid, etc."""
        if hasattr(macho, "get_general_info"):
            results["general_info"] = macho.get_general_info(formatted=True)
        elif hasattr(macho, "general_info"):
            results["general_info"] = macho.general_info

        if hasattr(macho, "get_macho_header"):
            results["header"] = macho.get_macho_header(formatted=True)
        elif hasattr(macho, "header"):
            results["header"] = macho.header

        if hasattr(macho, "get_architectures"):
            results["architectures"] = macho.get_architectures()
        elif hasattr(macho, "header") and "cputype" in results.get("header", {}):
            results["architectures"] = [results["header"]["cputype"]]
        else:
            results["architectures"] = []

        if hasattr(macho, "uuid"):
            results["uuid"] = str(macho.uuid)

        if hasattr(macho, "entry_point"):
            results["entrypoint"] = str(macho.entry_point)

        if hasattr(macho, "version_info"):
            results["version_info"] = str(macho.version_info)

    def _extract_lists(self, macho, results: Dict[str, Any]):
        """Extracts list-based info like segments, dylibs, imports, exports."""
        if hasattr(macho, "load_commands"):
            results["load_commands"] = [str(lc) for lc in macho.load_commands]

        if hasattr(macho, "segments"):
            results["segments"] = [str(s) for s in macho.segments]

        if hasattr(macho, "dylib_names"):
            results["dylib_names"] = [_safe_decode(d) for d in macho.dylib_names]

        if hasattr(macho, "get_imported_functions"):
            results["imports"] = macho.get_imported_functions()
        elif hasattr(macho, "imported_functions"):
            results["imports"] = (
                [_safe_decode(f) for f in macho.imported_functions]
                if macho.imported_functions
                else []
            )

        if hasattr(macho, "get_exported_symbols"):
            results["exports"] = macho.get_exported_symbols()
        elif hasattr(macho, "exported_symbols"):
            results["exports"] = (
                [_safe_decode(s) for s in macho.exported_symbols]
                if macho.exported_symbols
                else []
            )

    def run(self) -> Dict[str, Any]:
        results = {}

        if machofile is None:
            error_msg = "machofile library is not installed"
            logger.error(error_msg)
            self.report.errors.append(error_msg)
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()
            return results

        try:
            macho = self._parse_macho()
            if macho is None:
                raise Exception("Failed to create MachO object")

            self._extract_basic_info(macho, results)
            self._extract_lists(macho, results)

            if hasattr(macho, "code_signature_info"):
                results["code_signature"] = macho.code_signature_info

            if hasattr(macho, "get_similarity_hashes"):
                results["hashes"] = macho.get_similarity_hashes(formatted=True)

        except Exception as e:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                f"md5:{self.md5} filename:{self.filename} MachoFile parsing error: {e}"
            )
            logger.warning(warning_message, exc_info=True)
            self.report.errors.append(warning_message)
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()

        return results

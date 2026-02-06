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
                raise AnalyzerRunException(f"Parse failed. Single: {e}, Universal: {universal_error}")

    def _get_attr(self, macho, getter: str, fallback: str, formatted=True):
        """Try getter method first, then fall back to direct attribute."""
        if getter and hasattr(macho, getter):
            try:
                return getattr(macho, getter)(formatted=formatted)
            except TypeError:
                return getattr(macho, getter)()
        if fallback and hasattr(macho, fallback):
            return getattr(macho, fallback)
        return None

    def run(self) -> Dict[str, Any]:
        results = {}

        try:
            macho = self._parse_macho()
            if val := self._get_attr(macho, "get_general_info", "general_info"):
                results["general_info"] = val
            if val := self._get_attr(macho, "get_macho_header", "header"):
                results["header"] = val
            if val := self._get_attr(macho, "get_similarity_hashes", None):
                results["hashes"] = val
            if val := self._get_attr(macho, None, "code_signature_info"):
                results["code_signature"] = val
            if hasattr(macho, "get_architectures"):
                results["architectures"] = macho.get_architectures()
            elif isinstance(results.get("header"), dict):
                results["architectures"] = list(results["header"].keys())
            else:
                results["architectures"] = []
            for key, attr in [
                ("uuid", "uuid"),
                ("entrypoint", "entry_point"),
                ("version_info", "version_info"),
            ]:
                if hasattr(macho, attr):
                    val = getattr(macho, attr)
                    results[key] = val
            is_universal = hasattr(macho, "architectures") and isinstance(macho.architectures, dict)

            def get_macho_lists(m):
                return {
                    "load_commands": [str(lc) for lc in m.load_commands]
                    if hasattr(m, "load_commands")
                    else [],
                    "segments": [str(s) for s in m.segments] if hasattr(m, "segments") else [],
                    "dylib_names": [_safe_decode(d) for d in m.dylib_names]
                    if hasattr(m, "dylib_names")
                    else [],
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
            if hasattr(macho, "get_imported_functions"):
                results["imports"] = macho.get_imported_functions()
            elif hasattr(macho, "imported_functions") and macho.imported_functions:
                results["imports"] = [_safe_decode(f) for f in macho.imported_functions]

            if hasattr(macho, "get_exported_symbols"):
                results["exports"] = macho.get_exported_symbols()
            elif hasattr(macho, "exported_symbols") and macho.exported_symbols:
                results["exports"] = [_safe_decode(s) for s in macho.exported_symbols]

        except AnalyzerRunException:
            raise
        except Exception as e:
            error_msg = f"job_id:{self.job_id} analyzer:{self.analyzer_name} md5:{self.md5} filename:{self.filename} MachoFile parsing error: {e}"
            self.report.errors.append(error_msg)
            raise AnalyzerRunException(error_msg)

        return results

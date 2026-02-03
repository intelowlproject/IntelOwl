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


class MachoInfo(FileAnalyzer):
    """
    Analyzer for Mach-O binary files (macOS/iOS executables).
    Uses the machofile library to parse and extract information.

    API Validation Strategy:
    This analyzer uses defensive programming with hasattr() checks because:
    - The machofile library API varies between single-arch and Universal (FAT) binaries
    - Different Mach-O file types may expose different methods/properties
    - This ensures robustness across various binary formats
    - All API assumptions have been validated through testing (see library_choice.md)

    Library: https://github.com/pstirparo/machofile
    Version: 2025.8.5 (installed from GitHub)
    """

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
            # Parse the Mach-O file
            macho = None
            parse_error = None

            # Try single-architecture first
            try:
                macho = machofile.MachO(self.filepath)
                if hasattr(macho, "parse"):
                    macho.parse()
            except Exception as e:
                # If single-arch fails, try Universal (FAT) binary
                try:
                    macho = machofile.UniversalMachO(self.filepath)
                    if hasattr(macho, "parse"):
                        macho.parse()
                except Exception as universal_error:
                    # Both parsers failed
                    parse_error = (
                        f"Failed to parse as both single and universal binary. "
                        f"Single: {str(e)}, Universal: {str(universal_error)}"
                    )
                    logger.warning(
                        f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                        f"md5:{self.md5} {parse_error}"
                    )
                    try:
                        macho = machofile.MachO(self.filepath)
                    except Exception:
                        raise Exception(parse_error)

            if macho is None:
                raise Exception("Failed to create MachO object")

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

            if hasattr(macho, "load_commands"):
                results["load_commands"] = [str(lc) for lc in macho.load_commands]

            if hasattr(macho, "segments"):
                results["segments"] = [str(s) for s in macho.segments]

            if hasattr(macho, "dylib_names"):
                results["dylib_names"] = [
                    d.decode("utf-8", "ignore") if isinstance(d, bytes) else str(d)
                    for d in macho.dylib_names
                ]

            if hasattr(macho, "uuid"):
                results["uuid"] = str(macho.uuid)

            if hasattr(macho, "entry_point"):
                results["entrypoint"] = str(macho.entry_point)

            if hasattr(macho, "version_info"):
                results["version_info"] = str(macho.version_info)

            if hasattr(macho, "code_signature_info"):
                results["code_signature"] = macho.code_signature_info

            if hasattr(macho, "get_imported_functions"):
                results["imports"] = macho.get_imported_functions()
            elif hasattr(macho, "imported_functions"):
                import_funcs = macho.imported_functions
                if import_funcs:
                    results["imports"] = [
                        f.decode("utf-8", "ignore") if isinstance(f, bytes) else str(f)
                        for f in import_funcs
                    ]
                else:
                    results["imports"] = []

            if hasattr(macho, "get_exported_symbols"):
                results["exports"] = macho.get_exported_symbols()
            elif hasattr(macho, "exported_symbols"):
                if macho.exported_symbols:
                    results["exports"] = [
                        s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)
                        for s in macho.exported_symbols
                    ]
                else:
                    results["exports"] = []

            if hasattr(macho, "get_similarity_hashes"):
                results["hashes"] = macho.get_similarity_hashes(formatted=True)

        except Exception as e:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                f"md5:{self.md5} filename:{self.filename} "
                f"MachoFile parsing error: {e}"
            )
            logger.warning(warning_message, exc_info=True)
            self.report.errors.append(str(e))
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()

        return results

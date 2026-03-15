# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import machofile

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class MachoInfo(FileAnalyzer):
    def run(self):
        results = {}
        try:
            macho = machofile.UniversalMachO(file_path=self.filepath)
            macho.parse()

            results["general_info"] = macho.get_general_info()
            results["header"] = macho.get_macho_header()
            results["architectures"] = macho.get_architectures()
            results["load_commands"] = macho.get_load_commands()
            results["load_commands_set"] = macho.get_load_commands_set()
            results["segments"] = macho.get_segments()
            results["imported_functions"] = macho.get_imported_functions()
            results["exported_symbols"] = macho.get_exported_symbols()
            results["dylib_names"] = macho.get_dylib_names()
            results["entry_point"] = macho.get_entry_point()
            results["uuid"] = macho.get_uuid()
            results["version_info"] = macho.get_version_info()
            results["similarity_hashes"] = macho.get_similarity_hashes()
            results["import_hash"] = macho.get_import_hash()
            results["export_hash"] = macho.get_export_hash()
            results["dylib_hash"] = macho.get_dylib_hash()
            results["symhash"] = macho.get_symhash()
            results["code_signature"] = macho.get_code_signature_info()

        except Exception as exc:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name}"
                f" md5:{self.md5} filename: {self.filename}"
                f" MachoInfoError {exc}"
            )
            logger.warning(warning_message)
            self.report.errors.append(warning_message)
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()

        return results

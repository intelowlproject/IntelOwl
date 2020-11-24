# this analyzer leverage a forked version of PEfile ...
# ... that fixes one common problem encountered in a lot of analysis
# original repository: https://github.com/erocarrera/pefile
# forked repository: https://github.com/mlodic/pefile

import logging
import pefile

from datetime import datetime

from api_app.script_analyzers.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class PEInfo(FileAnalyzer):
    def run(self):
        results = {}
        try:
            pe = pefile.PE(self.filepath)
            if not pe:
                raise pefile.PEFormatError("Empty file?")
            full_dump = pe.dump_dict()

            results["imphash"] = pe.get_imphash()

            results["warnings"] = pe.get_warnings()

            if pe.is_dll():
                results["type"] = "DLL"
            elif pe.is_driver():
                results["type"] = "DRIVER"
            elif pe.is_exe():
                results["type"] = "EXE"

            sections = []
            for section in pe.sections:
                try:
                    name = section.Name.decode()
                except UnicodeDecodeError as e:
                    name = "UnableToDecode"
                    logger.warning(
                        f"Unable to decode section {section.Name} exception {e}"
                    )
                section_item = {
                    "name": name,
                    "address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "size": section.SizeOfRawData,
                    "entropy": section.get_entropy(),
                }
                sections.append(section_item)

            results["sections"] = sections

            machine_value = pe.FILE_HEADER.Machine
            results["machine"] = machine_value
            mt = {"0x14c": "x86", "0x0200": "Itanium", "0x8664": "x64"}
            architecture = ""
            if isinstance(machine_value, int):
                architecture = mt.get(str(hex(machine_value)), "")
            if not architecture:
                architecture = str(machine_value) + " => Not x86/64 or Itanium"
            results["architecture"] = architecture

            results["os"] = "{}.{}".format(
                pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            )

            results["entrypoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            results["imagebase"] = hex(pe.OPTIONAL_HEADER.ImageBase)

            timestamp = pe.FILE_HEADER.TimeDateStamp
            results["compilation_timestamp"] = datetime.utcfromtimestamp(
                timestamp
            ).strftime("%Y-%m-%d %H:%M:%S")

            import_table = []
            directory_entry_import = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for entry in directory_entry_import:
                imp = {
                    "entryname": entry.dll.decode() if entry.dll else None,
                    "symbols": [],
                }
                for symbol in entry.imports:
                    if symbol.name:
                        imp["symbols"].append(symbol.name.decode())
                import_table.append(imp)
            results["import_table"] = import_table

            export_table = []
            for entry in full_dump.get("Exported symbols", []):
                symbol_name = entry.get("Name", None)
                # in case it is a dictionary, we do not mind it
                try:
                    export_table.append(symbol_name.decode())
                except (UnicodeDecodeError, AttributeError) as e:
                    logger.debug(
                        f"PE info error while decoding export table symbols: {e}"
                    )
            # this is to reduce the output
            export_table = export_table[:100]
            results["export_table"] = export_table

            results["flags"] = full_dump.get("Flags", [])

        except pefile.PEFormatError as e:
            warning_message = (
                "job_id:{} analyzer:{} md5:{} filename: {} PEFormatError {}"
                "".format(self.job_id, self.analyzer_name, self.md5, self.filename, e)
            )
            logger.warning(warning_message)
            self.report["errors"].append(warning_message)
            self.report["success"] = False

        return results

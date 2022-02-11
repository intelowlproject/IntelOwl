# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# this analyzer leverage a forked version of PEfile ...
# ... that fixes one common problem encountered in a lot of analysis
# original repository: https://github.com/erocarrera/pefile
# forked repository: https://github.com/mlodic/pefile

import logging
import os
from datetime import datetime

import lief
import pefile
import pyimpfuzzy
from PIL import Image

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class WinPEhasher_NT_Header_Error(AnalyzerRunException):
    """
    Class that resembles a NT Header exception (invalid PE File) for WinPEhasher
    """


class WinPEhasher_No_Icon_Error(AnalyzerRunException):
    """
    Class that resembles a No Icon resource exception for WinPEhasher dhashicon
    """


class WinPEhasher:
    file_path: str

    def __init__(self, file_path: str, parent=None) -> None:
        """
        Init a WinPE instance and load the exe file
        """
        self.file_path = file_path
        self.parent = parent

    def dhashicon(self) -> str:
        """
        Return Dhashicon of the exe
        """
        # this code was implemented from
        # https://github.com/fr0gger/SuperPeHasher/commit/e9b753bf52d4e48dda2da0b7801075be4037a161#diff-2bb2d2d4d25fef20a893a4e93e96c9b8c0b0c6d5791fc14594cc9dd5cbf40b41
        #
        # config
        hash_size = 8
        # extract icon
        icon_path = self.file_path + ".ico"
        binary = lief.parse(self.file_path)
        if binary is None:
            # Invalid PE file
            raise WinPEhasher_NT_Header_Error()
        # extracting icon and saves in a temp file
        binres = binary.resources_manager
        if not binres.has_type(lief.PE.RESOURCE_TYPES.ICON):
            # no icon resources in file
            raise WinPEhasher_No_Icon_Error()
        ico = binres.icons
        ico[0].save(icon_path)
        # resize
        exe_icon = Image.open(icon_path)
        exe_icon = exe_icon.convert("L").resize(
            (hash_size + 1, hash_size), Image.ANTIALIAS
        )
        diff = []
        for row in range(hash_size):
            for col in range(hash_size):
                left = exe_icon.getpixel((col, row))
                right = exe_icon.getpixel((col + 1, row))
                diff.append(left > right)
        decimal_value = 0
        icon_hash = []
        for index, value in enumerate(diff):
            if value:
                decimal_value += 2 ** (index % 8)
            if (index % 8) == 7:
                icon_hash.append(hex(decimal_value)[2:].rjust(2, "0"))
                decimal_value = 0
        os.remove(icon_path)
        return "".join(icon_hash)

    def impfuzzy(self):
        """
        Calculate impfuzzy hash and return
        """
        try:
            # this code was implemented from
            # https://github.com/JPCERTCC/impfuzzy
            #
            impfuzzyhash = pyimpfuzzy.get_impfuzzy(self.file_path)
            return str(impfuzzyhash)
        except pyimpfuzzy.pefile.PEFormatError:
            raise WinPEhasher_NT_Header_Error()


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

            # Try using WinPEhasher on the PE file
            try:
                winpe_hasher = WinPEhasher(self.filepath, self)
                results["dhashicon_hash"] = winpe_hasher.dhashicon()
                results["impfuzzy_hash"] = winpe_hasher.impfuzzy()
            except Exception() as e:
                logger.info(
                    f"Exception while running WinPEhasher. Error: {str(e)}.",
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
            self.report.errors.append(warning_message)
            self.report.status = self.report.Status.FAILED
            self.report.save()

        return results

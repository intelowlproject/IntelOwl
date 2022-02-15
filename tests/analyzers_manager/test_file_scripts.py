# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from . import _FileAnalyzersScriptsTestCase

# File Analyzer Test Cases


class EXEAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.exe",
            "file_mimetype": "application/x-dosexec",
            "analyzers_to_execute": [
                "File_Info",
                "PE_Info",
                "Signature_Info",
                "SpeakEasy",
                "Strings_Info_Classic",
                "Strings_Info_ML",
                "Qiling_Windows",
                "Qiling_Windows_Shellcode",
                "Qiling_Linux",
                "Qiling_Linux_Shellcode",
                "Intezer_Scan",
                "Cuckoo_Scan",
                "Malpedia_Scan",
                "UnpacMe_EXE_Unpacker",
                "PEframe_Scan",
                "Capa_Info",
                "CapeSandbox",
                "Triage_Scan",
                "Floss",
                "Manalyze",
                "MWDB_Scan",
                "Yara_Scan_ATM_MALWARE",
                "Yara_Scan_Community",
                "Yara_Scan_Daily_Ioc",
                "Yara_Scan_FireEye",
                "Yara_Scan_Florian",
                "Yara_Scan_Inquest",
                "Yara_Scan_Intezer",
                "Yara_Scan_McAfee",
                "Yara_Scan_ReversingLabs",
                "Yara_Scan_Samir",
                "Yara_Scan_Stratosphere",
                "VirusTotal_v2_Get_File",
                "VirusTotal_v2_Scan_File",
                "VirusTotal_v3_Get_File",
                "VirusTotal_v3_Get_File_And_Scan",
                "Cymru_Hash_Registry_Get_File",
                "HybridAnalysis_Get_File",
                "MISPFIRST_Check_Hash",
                "MISP_Check_Hash",
                "MalwareBazaar_Get_File",
                "OTX_Check_Hash",
                "Dragonfly_Emulation",
                "FileScan_Upload_File",
                "Virushee_UploadFile",
            ],
        }


class DLLAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.dll",
            "file_mimetype": "application/x-dosexec",
            "analyzers_to_execute": ["File_Info", "PE_Info", "SpeakEasy"],
        }


class DocAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.doc",
            "file_mimetype": "application/msword",
            "analyzers_to_execute": ["Doc_Info", "Doc_Info_Experimental"],
        }


class ExcelAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.xls",
            "file_mimetype": "application/vnd.ms-excel",
            "analyzers_to_execute": ["Xlm_Macro_Deobfuscator"],
        }


class RtfAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.rtf",
            "file_mimetype": "text/rtf",
            "analyzers_to_execute": ["Rtf_Info"],
        }


class PDFAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "document.pdf",
            "file_mimetype": "application/pdf",
            "analyzers_to_execute": ["PDF_Info"],
        }


class HTMLAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "page.html",
            "file_mimetype": "text/html",
            "analyzers_to_execute": ["Thug_HTML_Info"],
        }


class JSAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "file.jse",
            "file_mimetype": "application/javascript",
            "analyzers_to_execute": ["BoxJS_Scan_JavaScript"],
        }


class APKAnalyzersTestCase(_FileAnalyzersScriptsTestCase):
    @classmethod
    def get_params(cls):
        return {
            **super().get_params(),
            "file_name": "sample.apk",
            "file_mimetype": "application/vnd.android.package-archive",
            "analyzers_to_execute": ["APKiD_Scan_APK_DEX_JAR", "Quark_Engine_APK"],
        }

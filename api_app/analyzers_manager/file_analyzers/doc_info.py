# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# this analyzer leverage a forked version of Oletools ...
# ... that implements additional features to correctly analyze some particular files
# original repository: https://github.com/decalage2/oletools
# forked repository: https://github.com/mlodic/oletools
import logging
import re
import zipfile
from re import sub
from typing import Dict, List

import docxpy
import olefile
from defusedxml.ElementTree import fromstring
from defusedxml.minidom import parseString
from oletools import mraptor, oleid, oleobj
from oletools.common.clsid import KNOWN_CLSIDS
from oletools.msodde import process_maybe_encrypted as msodde_process_maybe_encrypted
from oletools.olevba import VBA_Parser
from oletools.ooxml import XmlParser

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.models import MimeTypes

logger = logging.getLogger(__name__)

try:
    from XLMMacroDeobfuscator.deobfuscator import show_cells
    from XLMMacroDeobfuscator.xls_wrapper_2 import XLSWrapper2
except Exception as e:
    logger.exception(e)

XML_H_SCHEMA = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
SCHEMA_DOMAINS = [
    "schemas.openxmlformats.org",
    "schemas-microsoft-com",
    "schemas.microsoft.com",
]


class CannotDecryptException(Exception):
    pass


class DocInfo(FileAnalyzer):
    experimental: bool
    additional_passwords_to_check: list

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.olevba_results = {}
        self.vbaparser = None
        self.passwords_to_check = []

        self.passwords_to_check.extend(self.additional_passwords_to_check)

    def update(self) -> bool:
        pass

    def run(self):
        results = {"uris": []}

        # olevba
        try:
            self.vbaparser = VBA_Parser(self.filepath)

            self.manage_encrypted_doc()

            self.manage_xlm_macros()

            # go on with the normal oletools execution
            self.olevba_results["macro_found"] = self.vbaparser.detect_vba_macros()

            if self.olevba_results["macro_found"]:
                vba_code_all_modules = ""
                macro_data = []
                for (
                    v_filename,
                    stream_path,
                    vba_filename,
                    vba_code,
                ) in self.vbaparser.extract_macros():
                    extracted_macro = {
                        "filename": v_filename,
                        "ole_stream": stream_path,
                        "vba_filename": vba_filename,
                        "vba_code": vba_code,
                    }
                    macro_data.append(extracted_macro)
                    vba_code_all_modules += vba_code + "\n"
                self.olevba_results["macro_data"] = macro_data

                # example output
                #
                # {'description': 'Runs when the Word document is opened',
                #  'keyword': 'AutoOpen',
                #  'type': 'AutoExec'},
                # {'description': 'May run an executable file or a system command',
                #  'keyword': 'Shell',
                #  'type': 'Suspicious'},
                # {'description': 'May run an executable file or a system command',
                #  'keyword': 'WScript.Shell',
                #  'type': 'Suspicious'},
                # {'description': 'May run an executable file or a system command',
                #  'keyword': 'Run',
                #  'type': 'Suspicious'},
                # {'description': 'May run PowerShell commands',
                #  'keyword': 'powershell',
                #  'type': 'Suspicious'},
                # {'description': '9BA55BE5', 'keyword': 'xxx', 'type': 'Hex String'},

                # mraptor
                macro_raptor = mraptor.MacroRaptor(vba_code_all_modules)
                if macro_raptor:
                    macro_raptor.scan()
                    results["mraptor"] = "suspicious" if macro_raptor.suspicious else "ok"

                # analyze macros
                analyzer_results = self.vbaparser.analyze_macros(True, True)
                # it gives None if it does not find anything
                if analyzer_results:
                    analyze_macro_results = []
                    for kw_type, keyword, description in analyzer_results:
                        if kw_type not in ("Hex String", "Base64 String"):
                            analyze_macro_result = {
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description,
                            }
                            analyze_macro_results.append(analyze_macro_result)
                    self.olevba_results["analyze_macro"] = analyze_macro_results

            results["olevba"] = self.olevba_results

            if self.file_mimetype != MimeTypes.ONE_NOTE.value:
                results["msodde"] = self.analyze_msodde()

        except CannotDecryptException as e:
            logger.info(e)
        except Exception as e:
            error_message = f"job_id {self.job_id} doc info extraction failed. Error: {e}"
            logger.warning(error_message, stack_info=True)
            self.report.errors.append(error_message)
            self.report.save()
        finally:
            if self.vbaparser:
                self.vbaparser.close()

        try:
            if self.file_mimetype in [
                MimeTypes.WORD1.value,
                MimeTypes.WORD2.value,
                MimeTypes.ZIP1.value,
                MimeTypes.ZIP2.value,
            ]:
                results["follina"] = self.analyze_for_follina_cve()
                results["uris"].extend(self.get_docx_urls())

            results["extracted_CVEs"] = self.analyze_for_cve()
            results["uris"].extend(self.get_external_relationships())
            results["uris"].extend(self.extract_urls_from_IOCs())
            results["uris"] = list(set(results["uris"]))  # make it uniq
        except Exception as e:
            error_message = f"job_id {self.job_id} special extractions failed. Error: {e}"
            logger.warning(error_message, stack_info=True)
            self.report.errors.append(error_message)
            self.report.save()

        return results

    def extract_urls_from_IOCs(self):
        urls = []
        # we have to re-parse the file entirely because the functions called before this one
        # alter the internal state of the parser and as a result the IOC section is empty
        vbaparser = VBA_Parser(self.filepath)
        analyzer_results = vbaparser.analyze_macros(True, True)

        # it gives None if it does not find anything
        if analyzer_results:
            for kw_type, keyword, description in analyzer_results:
                if kw_type == "IOC" and description == "URL":
                    urls.append(keyword)
        if vbaparser:
            vbaparser.close()
        return urls

    def analyze_for_follina_cve(self) -> List[str]:
        hits = []
        try:
            # case docx
            zipped = zipfile.ZipFile(self.filepath)
        except zipfile.BadZipFile:
            logger.info(f"file {self.filename} is not a zip file so wecant' do custom Follina Extraction")
        else:
            try:
                template = zipped.read("word/_rels/document.xml.rels")
            except KeyError:
                pass
            else:
                # logic reference:
                # https://github.com/MalwareTech/FollinaExtractor/blob/main/extract_follina.py#L7
                xml_root = fromstring(template)
                for xml_node in xml_root.iter():
                    target = xml_node.attrib.get("Target")
                    if target:
                        target = target.strip().lower()
                        # join the list as uniq string due to the other non-matched
                        # group in the OR mutual exclusive expressions
                        matches = re.findall(
                            r"((?<!mhtml:)https?://.*\.html!)|(mhtml:https?://.*?!)",
                            target,
                        )
                        hits += ["".join(x) for x in matches]
        return hits

    def analyze_for_cve(self) -> List:
        pattern = r"CVE-\d{4}-\d{4,7}"
        results = []
        try:
            olefile.isOleFile(self.filepath)
            ole = olefile.OleFileIO(self.filepath)
        except olefile.olefile.NotOleFileError:
            logger.info("not an OLE2 structured storage file, do not proceed.")
        else:
            for entry in sorted(ole.listdir(storages=True)):
                clsid = ole.getclsid(entry)
                if clsid_text := KNOWN_CLSIDS.get(clsid.upper(), None):
                    if "cve" in clsid_text.lower():
                        results.append(
                            {
                                "clsid": clsid,
                                "info": clsid_text,
                                "CVEs": list(re.findall(pattern, clsid_text)),
                            }
                        )
        return results

    def get_external_relationships(self) -> List:
        external_relationships = []
        try:
            olefile.isOleFile(self.filepath)
            oid = oleid.OleID(self.filepath)
        except olefile.olefile.NotOleFileError:
            logger.info("not an OLE2 structured storage file, do not proceed.")
        else:
            if sum(i.value for i in oid.check() if i.id == "ext_rels") > 1:
                xml_parser = XmlParser(self.filepath)
                for relationship, target in oleobj.find_external_relationships(xml_parser):
                    external_relationships.append(
                        {
                            "relationship": relationship,
                            "target": target,
                        }
                    )
        return external_relationships

    def get_docx_urls(self) -> List:
        urls = []
        pages_count = 0

        try:
            document = zipfile.ZipFile(self.filepath)
        except zipfile.BadZipFile as e:  # check if docx document
            error_message = f"job_id {self.job_id} docx bad zip file: {e}"
            logger.warning(error_message, stack_info=True)
            self.report.errors.append(error_message)
        else:
            try:
                dxml = document.read("docProps/app.xml")
                pages_count = int(parseString(dxml).getElementsByTagName("Pages")[0].childNodes[0].nodeValue)
            except KeyError:
                logger.info(
                    "number of pages not found, maybe the file is malformed, "
                    "proceed anyway in order to not lose the possibly contained IOCs"
                )

            if pages_count <= 1:
                # extract urls from text
                try:
                    doc = docxpy.DOCReader(self.filepath)
                    doc.process()
                except Exception as e:
                    error_message = f"job_id {self.job_id} docxpy url extraction failed. Error: {e}"
                    logger.warning(error_message, stack_info=True)
                    self.report.errors.append(error_message)
                else:
                    # decode bytes like links
                    links = [
                        link.decode() if isinstance(link, bytes) else link for link in doc.data["links"][0]
                    ]
                    # remove empty strings
                    links = [link for link in links if link != ""]
                    urls.extend(links)

                # also parse xml in case docxpy missed some links
                try:
                    for relationship in list(fromstring(document.read("word/_rels/document.xml.rels"))):
                        # exclude xml schema urls
                        if relationship.attrib["Type"] == XML_H_SCHEMA and any(
                            domain in relationship.attrib["Target"] for domain in SCHEMA_DOMAINS
                        ):
                            urls.append(relationship.attrib["Target"])
                except KeyError as e:
                    error_message = f"job_id {self.job_id} no xml rels found. Error: {e}"
                    logger.warning(error_message, stack_info=True)
                    self.report.errors.append(error_message)
        return urls

    def analyze_msodde(self):
        try:
            msodde_result = msodde_process_maybe_encrypted(self.filepath, self.passwords_to_check)
        except Exception as e:
            error_message = f"job_id {self.job_id} msodde parser failed. Error: {e}"
            # This may happen for text/plain samples types
            # and should not be treated as an engine error
            if "Could not determine delimiter" in str(e) or self.filename.endswith(".exe"):
                logger.info(error_message, stack_info=True)
            else:
                logger.warning(error_message, stack_info=True)
            self.report.errors.append(error_message)
            self.report.save()
            msodde_result = f"Error: {e}"
        return msodde_result

    def manage_encrypted_doc(self):
        self.olevba_results["is_encrypted"] = False
        # checks if it is an OLE file. That could be encrypted
        if self.vbaparser.ole_file:
            # check if the ole file is encrypted
            is_encrypted = self.vbaparser.detect_is_encrypted()
            self.olevba_results["is_encrypted"] = is_encrypted
            # in the case the file is encrypted I try to decrypt it
            # with the default password and the most common ones
            if is_encrypted:
                # by default oletools contains some basic passwords
                # we just add some more guesses
                common_pwd_to_check = []
                for num in range(10):
                    common_pwd_to_check.append(f"{num}{num}{num}{num}")
                # https://twitter.com/JohnLaTwC/status/1265377724522131457
                filename_without_spaces_and_numbers = sub(r"[-_\d\s]", "", self.filename)
                filename_without_extension = sub(r"(\..+)", "", filename_without_spaces_and_numbers)
                common_pwd_to_check.append(filename_without_extension)
                self.passwords_to_check.extend(common_pwd_to_check)
                decrypted_file_name, correct_password = self.vbaparser.decrypt_file(
                    self.passwords_to_check,
                )
                self.olevba_results["additional_passwords_tried"] = self.passwords_to_check
                if correct_password:
                    self.olevba_results["correct_password"] = correct_password
                if decrypted_file_name:
                    self.vbaparser = VBA_Parser(decrypted_file_name)
                else:
                    self.olevba_results["cannot_decrypt"] = True
                    raise CannotDecryptException("cannot decrypt the file with the default password")

    def manage_xlm_macros(self):
        # this would overwrite classic XLM parsing
        self.olevba_results["xlm_macro"] = False
        # check if the file contains an XLM macro
        # and try an experimental parsing
        # credits to https://twitter.com/gabriele_pippi for the idea
        if self.vbaparser.detect_xlm_macros():
            self.olevba_results["xlm_macro"] = True
            logger.debug("experimental XLM macro analysis start")
            parsed_file = b""
            try:
                excel_doc = XLSWrapper2(self.filepath)
                ae_list = [
                    "auto_open",
                    "auto_close",
                    "auto_activate",
                    "auto_deactivate",
                ]
                self.olevba_results["xlm_macro_autoexec"] = []
                for ae in ae_list:
                    auto_exec_labels = excel_doc.get_defined_name(ae, full_match=False)
                    for label in auto_exec_labels:
                        self.olevba_results["xlm_macro_autoexec"].append(label[0])

                for i in show_cells(excel_doc):
                    rec_str = ""
                    if len(i) == 5:
                        # rec_str = 'CELL:{:10}, {:20}, {}'
                        # .format(i[0].get_local_address(), i[2], i[4])
                        if i[2] != "None":
                            rec_str = "{:20}".format(i[2])
                    if rec_str:
                        parsed_file += rec_str.encode()
                        parsed_file += b"\n"
            except Exception as e:
                logger.info(f"experimental XLM macro analysis failed. Exception: {e}")
            else:
                logger.debug(f"experimental XLM macro analysis succeeded. Binary to analyze: {parsed_file}")
                if parsed_file:
                    self.vbaparser = VBA_Parser(self.filename, data=parsed_file)

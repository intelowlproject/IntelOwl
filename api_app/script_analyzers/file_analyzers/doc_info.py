# this analyzer leverage a forked version of Oletools ...
# ... that implements additional features to correctly analyze some particular files
# original repository: https://github.com/decalage2/oletools
# forked repository: https://github.com/mlodic/oletools

import logging

from re import sub

from oletools import mraptor
from oletools.olevba import VBA_Parser

from api_app.script_analyzers.classes import FileAnalyzer

logger = logging.getLogger(__name__)

try:
    from XLMMacroDeobfuscator.xls_wrapper_2 import XLSWrapper2
    from XLMMacroDeobfuscator.deobfuscator import show_cells
except Exception as e:
    logger.exception(e)


class CannotDecryptException(Exception):
    pass


class DocInfo(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.olevba_results = {}
        self.vbaparser = None
        self.experimental = additional_config_params.get("experimental", False)
        self.passwords_to_check = []
        # this is to extract the passwords for encryption requested by the client
        # you can use pyintelowl to send additional passwords to check for
        # example:
        #             "additional_configuration": {
        #                 "Doc_Info_Experimental": {
        #                     "additional_passwords_to_check": ["testpassword"]
        #                 }
        #             },
        additional_passwords_to_check = additional_config_params.get(
            "additional_passwords_to_check", []
        )
        if isinstance(additional_passwords_to_check, list):
            self.passwords_to_check.extend(additional_passwords_to_check)

    def run(self):
        results = {}

        # olevba
        try:
            self.vbaparser = VBA_Parser(self.filepath)

            self.manage_encrypted_doc()

            if self.experimental:
                self.experimental_analysis()

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
                    results["mraptor"] = (
                        "suspicious" if macro_raptor.suspicious else "ok"
                    )

                # analyze macros
                analyzer_results = self.vbaparser.analyze_macros()
                # it gives None if it does not find anything
                if analyzer_results:
                    analyze_macro_results = []
                    for kw_type, keyword, description in analyzer_results:
                        if kw_type != "Hex String":
                            analyze_macro_result = {
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description,
                            }
                            analyze_macro_results.append(analyze_macro_result)
                    self.olevba_results["analyze_macro"] = analyze_macro_results

        except CannotDecryptException as e:
            logger.info(e)
        except Exception as e:
            error_message = f"job_id {self.job_id} vba parser failed. Error: {e}"
            logger.exception(error_message)
            self.report["errors"].append(error_message)
        finally:
            if self.vbaparser:
                self.vbaparser.close()

        results["olevba"] = self.olevba_results

        return results

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
                filename_without_spaces_and_numbers = sub("[-_\d\s]", "", self.filename)
                filename_without_extension = sub(
                    "(\..+)", "", filename_without_spaces_and_numbers
                )
                common_pwd_to_check.append(filename_without_extension)
                self.passwords_to_check.extend(common_pwd_to_check)
                decrypted_file_name = self.vbaparser.decrypt_file(
                    self.passwords_to_check
                )
                self.olevba_results[
                    "additional_passwords_tried"
                ] = self.passwords_to_check
                if decrypted_file_name:
                    self.vbaparser = VBA_Parser(decrypted_file_name)
                else:
                    self.olevba_results["cannot_decrypt"] = True
                    raise CannotDecryptException(
                        "cannot decrypt the file with the default password"
                    )

    def experimental_analysis(self):
        self.manage_xlm_macros()

    def manage_xlm_macros(self):
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
                logger.debug(
                    f"experimental XLM macro analysis succeded. "
                    f"Binary to analyze: {parsed_file}"
                )
                if parsed_file:
                    self.vbaparser = VBA_Parser(self.filename, data=parsed_file)

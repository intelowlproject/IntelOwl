import traceback
import logging
import pefile

from datetime import datetime

from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}
        pe = pefile.PE(filepath)
        if pe:
            full_dump = pe.dump_dict()

            results['imphash'] = pe.get_imphash()

            results['warnings'] = pe.get_warnings()

            if pe.is_dll():
                results['type'] = "DLL"
            elif pe.is_driver():
                results['type'] = "DRIVER"
            elif pe.is_exe():
                results['type'] = "EXE"

            sections = []
            for section in pe.sections:
                section_item = {
                    "name": section.Name.decode().replace('\u0000', ''),
                    "address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "size": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                }
                sections.append(section_item)
            results['sections'] = sections

            machine_value = pe.FILE_HEADER.Machine
            results['machine'] = machine_value
            mt = {'0x14c': 'x86', '0x0200': 'Itanium', '0x8664': 'x64'}
            architecture = ''
            if isinstance(machine_value, int):
                architecture = mt.get(str(hex(machine_value)), '')
            if not architecture:
                architecture = str(machine_value) + ' => Not x86/64 or Itanium'
            results['architecture'] = architecture

            results['os'] = "{}.{}".format(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                                           pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)

            results['entrypoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            results['imagebase'] = hex(pe.OPTIONAL_HEADER.ImageBase)

            timestamp = pe.FILE_HEADER.TimeDateStamp
            results['compilation_timestamp'] = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            import_table = []
            directory_entry_import = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for entry in directory_entry_import:
                imp = {
                    'entryname': entry.dll.decode() if entry.dll else None,
                    'symbols': []
                }
                for symbol in entry.imports:
                    if symbol.name:
                        imp['symbols'].append(symbol.name.decode())
                import_table.append(imp)
            results['import_table'] = import_table

            export_table = []
            for entry in full_dump.get('Exported symbols', []):
                symbol_name = entry.get('Name', None)
                # in case it is a dictionary, we do not mind it
                try:
                    export_table.append(symbol_name.decode())
                except (UnicodeDecodeError, AttributeError):
                    pass
            results['export_table'] = export_table

            results['flags'] = full_dump.get('Flags', [])

        report['report'] = results
    except pefile.PEFormatError as e:
        warning_message = "job_id:{} analyzer:{} md5:{} filename: {} PEFormatError {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.warning(warning_message)
        report['errors'].append(warning_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    general.set_report_and_cleanup(job_id, report)

    # pprint.pprint(report)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report

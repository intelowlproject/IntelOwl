import traceback

from celery.utils.log import get_task_logger
from oletools import mraptor
from oletools.olevba import VBA_Parser

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}

        # olevba
        olevba_results = {}
        try:

            vbaparser = VBA_Parser(filepath)

            olevba_results['macro_found'] = True if vbaparser.detect_vba_macros() else False

            if olevba_results['macro_found']:
                macro_data = []
                for (v_filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    extracted_macro = {
                        "filename": v_filename,
                        "ole_stream": stream_path,
                        "vba_filename": vba_filename,
                        "vba_code": vba_code
                    }
                    macro_data.append(extracted_macro)
                olevba_results['macro_data'] = macro_data

                # example output
                '''
                {'description': 'Runs when the Word document is opened',
                 'keyword': 'AutoOpen',
                 'type': 'AutoExec'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'Shell',
                 'type': 'Suspicious'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'WScript.Shell',
                 'type': 'Suspicious'},
                {'description': 'May run an executable file or a system command',
                 'keyword': 'Run',
                 'type': 'Suspicious'},
                {'description': 'May run PowerShell commands',
                 'keyword': 'powershell',
                 'type': 'Suspicious'},
                {'description': '9BA55BE5', 'keyword': 'xxx', 'type': 'Hex String'},
                 '''
                analyzer_results = vbaparser.analyze_macros(show_decoded_strings=True)
                # it gives None if it does not find anything
                if analyzer_results:
                    analyze_macro_results = []
                    for kw_type, keyword, description in analyzer_results:
                        if kw_type != 'Hex String':
                            analyze_macro_result = {
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description
                            }
                            analyze_macro_results.append(analyze_macro_result)
                    olevba_results['analyze_macro'] = analyze_macro_results

                olevba_results['reveal'] = vbaparser.reveal()

            vbaparser.close()

        except Exception as e:
            traceback.print_exc()
            error_message = "job_id {} vba parser failed. Error: {}".format(job_id, e)
            logger.exception(error_message)
            report['errors'].append(error_message)

        results['olevba'] = olevba_results

        # mraptor
        macro_raptor = mraptor.MacroRaptor(olevba_results.get('reveal', ''))
        if macro_raptor:
            macro_raptor.scan()
            results['mraptor'] = "suspicious" if macro_raptor.suspicious else 'ok'

        # pprint.pprint(results)
        report['report'] = results
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(error_message)
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

    general.set_report_and_cleanup(job_id, report, logger)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report

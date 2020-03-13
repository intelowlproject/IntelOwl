import traceback
import logging

from oletools.rtfobj import RtfObjParser

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}

        rtfobj_results = {}
        binary = general.get_binary(job_id)
        rtfp = RtfObjParser(binary)
        rtfp.parse()
        rtfobj_results['ole_objects'] = []
        for rtfobj in rtfp.objects:
            if rtfobj.is_ole:
                class_name = rtfobj.class_name.decode()
                ole_dict = {
                    "format_id": rtfobj.format_id,
                    "class_name": class_name,
                    "ole_datasize": rtfobj.oledata_size
                }
                if rtfobj.is_package:
                    ole_dict['is_package'] = True
                    ole_dict['filename'] = rtfobj.filename
                    ole_dict['src_path'] = rtfobj.src_path
                    ole_dict['temp_path'] = rtfobj.temp_path
                    ole_dict['olepkgdata_md5'] = rtfobj.olepkgdata_md5
                else:
                    ole_dict['ole_md5'] = rtfobj.oledata_md5
                if rtfobj.clsid:
                    ole_dict['clsid_desc'] = rtfobj.clsid_desc
                    ole_dict['clsid_id'] = rtfobj.clsid
                rtfobj_results['ole_objects'].append(ole_dict)
                # http://www.kb.cert.org/vuls/id/921560
                if class_name == 'OLE2Link':
                    rtfobj_results['exploit_ole2link_vuln'] = True
                # https://www.kb.cert.org/vuls/id/421280/
                elif class_name.lower() == 'equation.3':
                    rtfobj_results['exploit_equation_editor'] = True

        results['rtfobj'] = rtfobj_results

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

    general.set_report_and_cleanup(job_id, report)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report

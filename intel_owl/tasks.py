from __future__ import absolute_import, unicode_literals
from celery import shared_task

from api_app import crons
from api_app.script_analyzers import observable_analyzers, file_analyzers
from api_app.script_analyzers.classes import BaseAnalyzerMixin
from api_app.script_analyzers.utils import set_report_and_cleanup, set_failed_analyzer
from guardian import utils


@shared_task(soft_time_limit=200)
def clean_orphan_obj_perms():
    utils.clean_orphan_obj_perms()


@shared_task(soft_time_limit=10000)
def remove_old_jobs():
    crons.remove_old_jobs()


@shared_task(soft_time_limit=120)
def check_stuck_analysis():
    crons.check_stuck_analysis()


@shared_task(soft_time_limit=120)
def flush_expired_tokens():
    crons.flush_expired_tokens()


@shared_task(soft_time_limit=500)
def analyzer_run(typ, module_name, *args):
    try:
        modname, clsname = module_name.split(".")

        if typ == "observable":
            mod = getattr(observable_analyzers, modname)
        else:
            mod = getattr(file_analyzers, modname)
        if not mod:
            raise Exception(f"Module: {module_name} couldn't be imported")

        cls: BaseAnalyzerMixin = getattr(mod, clsname)
        if not cls:
            raise Exception(f"Class: {module_name} couldn't be imported")

        instance: BaseAnalyzerMixin = cls(*args)
        instance.start()
        set_report_and_cleanup(
            instance.analyzer_name,
            instance.job_id,
            instance.report,
        )
    except Exception as e:
        set_failed_analyzer(args[0], args[1], str(e))

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from api_app.models import Job


def serialize_job_metadata(job: Job) -> Dict[str, Any]:
    analyzable = getattr(job, "analyzable", None)
    tag_names = sorted(job.tags.values_list("label", flat=True))

    return {
        "id": job.pk,
        "status": job.status,
        "tlp": job.tlp,
        "is_sample": getattr(job, "is_sample", False),
        "observable_name": getattr(analyzable, "name", None),
        "observable_classification": getattr(analyzable, "classification", None),
        "file_mimetype": getattr(analyzable, "mimetype", None),
        "md5": getattr(analyzable, "md5", None),
        "created_at": job.received_request_time,
        "finished_at": job.finished_analysis_time,
        "process_time": job.process_time,
        "tags": tag_names,
        "errors": job.errors or [],
        "warnings": job.warnings or [],
    }


def compute_dict_diff(data_a: Any, data_b: Any) -> Dict[str, List[str]]:
    if not isinstance(data_a, dict) or not isinstance(data_b, dict):
        return {
            "keys_only_in_a": [],
            "keys_only_in_b": [],
            "keys_differing": [],
            "keys_matching": [],
        }

    keys_a = set(data_a.keys())
    keys_b = set(data_b.keys())

    keys_only_in_a = sorted(keys_a - keys_b)
    keys_only_in_b = sorted(keys_b - keys_a)
    common_keys = keys_a & keys_b

    keys_differing = sorted([k for k in common_keys if data_a[k] != data_b[k]])
    keys_matching = sorted([k for k in common_keys if data_a[k] == data_b[k]])

    return {
        "keys_only_in_a": keys_only_in_a,
        "keys_only_in_b": keys_only_in_b,
        "keys_differing": keys_differing,
        "keys_matching": keys_matching,
    }


def _compare_single_plugin(name: str, report_a: Any, report_b: Any) -> Dict[str, Any]:
    status_a = report_a.status if report_a else None
    status_b = report_b.status if report_b else None
    data_a = report_a.report if report_a else None
    data_b = report_b.report if report_b else None
    errors_a = report_a.errors if report_a else []
    errors_b = report_b.errors if report_b else []

    if report_a and report_b:
        presence = "both"
        has_differences = (status_a != status_b) or (data_a != data_b)
    elif report_a:
        presence = "job_a"
        has_differences = True
    else:
        presence = "job_b"
        has_differences = True

    diff_summary = compute_dict_diff(data_a, data_b) if presence == "both" else None

    return {
        "name": name,
        "present_in": presence,
        "has_differences": has_differences,
        "status_a": status_a,
        "status_b": status_b,
        "process_time_a": getattr(report_a, "process_time", None) if report_a else None,
        "process_time_b": getattr(report_b, "process_time", None) if report_b else None,
        "report_a": data_a,
        "report_b": data_b,
        "errors_a": errors_a,
        "errors_b": errors_b,
        "diff_summary": diff_summary,
    }


def compare_plugin_reports(reports_a_qs, reports_b_qs) -> List[Dict[str, Any]]:
    # Map report objects by plugin configuration name
    map_a = {r.config.name: r for r in reports_a_qs}
    map_b = {r.config.name: r for r in reports_b_qs}
    all_names = sorted(set(map_a.keys()) | set(map_b.keys()))

    return [_compare_single_plugin(name, map_a.get(name), map_b.get(name)) for name in all_names]


def compare_jobs(job_a: Job, job_b: Job) -> Dict[str, Any]:
    meta_a = serialize_job_metadata(job_a)
    meta_b = serialize_job_metadata(job_b)

    # Fetch analyzer and connector reports with configs preloaded
    analyzers_a = job_a.analyzerreports.select_related("config").all()
    analyzers_b = job_b.analyzerreports.select_related("config").all()
    analyzers_comp = compare_plugin_reports(analyzers_a, analyzers_b)

    connectors_a = job_a.connectorreports.select_related("config").all()
    connectors_b = job_b.connectorreports.select_related("config").all()
    connectors_comp = compare_plugin_reports(connectors_a, connectors_b)

    # Calculate summary metrics
    common_analyzers = [item for item in analyzers_comp if item["present_in"] == "both"]
    unique_analyzers_a = [item for item in analyzers_comp if item["present_in"] == "job_a"]
    unique_analyzers_b = [item for item in analyzers_comp if item["present_in"] == "job_b"]
    differing_analyzers = [item for item in common_analyzers if item["has_differences"]]

    tags_a = set(meta_a["tags"])
    tags_b = set(meta_b["tags"])

    summary = {
        "same_observable": (
            meta_a["observable_name"] == meta_b["observable_name"]
            and meta_a["observable_classification"] == meta_b["observable_classification"]
        ),
        "same_type": meta_a["is_sample"] == meta_b["is_sample"],
        "total_analyzers_a": len(analyzers_a),
        "total_analyzers_b": len(analyzers_b),
        "common_analyzers_count": len(common_analyzers),
        "unique_analyzers_a_count": len(unique_analyzers_a),
        "unique_analyzers_b_count": len(unique_analyzers_b),
        "differing_analyzers_count": len(differing_analyzers),
        "tag_diff": {
            "shared": sorted(tags_a & tags_b),
            "only_in_a": sorted(tags_a - tags_b),
            "only_in_b": sorted(tags_b - tags_a),
        },
    }

    return {
        "job_a": meta_a,
        "job_b": meta_b,
        "summary": summary,
        "analyzers": analyzers_comp,
        "connectors": connectors_comp,
    }

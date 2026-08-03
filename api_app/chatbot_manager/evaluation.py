# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Objective reading of a job's verdict for the chatbot.

Nothing here computes a verdict: the headline is IntelOwl's own reconciled evaluation
(`EvaluationEngineModule`) mapped through the shared `classify()`, so the chatbot says exactly
the word the job-page badge shows. This module only reads it, attributes it to the analyzers
that produced it, and reports honestly what did not answer. The LLM is never involved.

Tenancy: no `Job` query happens here — the caller passes a job already resolved through
`visible_for_user`, so the tool keeps the single tenancy boundary it already had.
"""

from dataclasses import dataclass, field

from api_app.choices import Classification
from api_app.data_model_manager.classify import classify
from api_app.data_model_manager.enums import DataModelVerdictBuckets
from api_app.engines_manager.engines.evaluation import EvaluationEngineModule
from api_app.models import Job

# The evidence lists are fed to a 3B model with an 8k context window: a job can carry 100+
# analyzer reports, so the lists are capped and the full size is reported as a count instead.
MAX_EVIDENCE_ANALYZERS = 10
MAX_SILENT_ANALYZERS = 10

# Honest reasons for the absence of a verdict. The reader never fabricates one.
REASON_GENERIC = "IntelOwl does not evaluate generic observables."
REASON_NO_EVALUATION = "No analyzer produced an evaluation for this observable."


@dataclass
class AnalyzerVerdict:
    """One analyzer's own evaluation, as stored in the DataModel its report produced."""

    name: str
    evaluation: str
    reliability: int


@dataclass
class JobEvaluation:
    """A job's reconciled verdict plus the evidence behind it.

    `bucket` is one of the five presentation buckets shared with the visualizer badge;
    `supporting` / `contradicting` / `silent` partition the analyzers that ran, so "we don't
    know" is always attributable to named analyzers instead of being an opaque shrug.
    """

    bucket: str
    evaluation: str | None
    reliability: int
    headline: str
    analyst_override: bool = False
    reason: str | None = None
    supporting: list[AnalyzerVerdict] = field(default_factory=list)
    contradicting: list[AnalyzerVerdict] = field(default_factory=list)
    silent: list[str] = field(default_factory=list)
    silent_count: int = 0
    analyzers_considered: int = 0


def _format_headline(
    bucket: str,
    reliability: int,
    supporting_count: int,
    contradicting_count: int,
    silent_count: int,
    analyzers_considered: int,
    analyst_override: bool,
    reason: str | None,
) -> str:
    """Build the one sentence the model is expected to relay verbatim.

    A copy-ready string keeps a small model from paraphrasing the numbers into something the
    badge does not say (the same failure class as the placeholder analyzer names).

    All three counts are stated explicitly, and the silent one even when it is zero. An earlier
    version reported only "N of M analyzers support it": a live smoke showed the model then
    inferred the remaining M-N analyzers were all contradicting and asserted there were no silent
    ones, which is the opposite of the honest-absence reporting this module exists to provide.
    """
    if reason:
        return f"{bucket} — {reason}"
    if analyst_override:
        # A manual analyst event outranks the analyzers in the engine's reconciliation, so the
        # analyzers are reported as agreeing/disagreeing, never as the source of the verdict —
        # crediting them would misattribute where it came from. The counts are still stated,
        # because omitting them is what made the model invent "no silent analyzers".
        return (
            f"{bucket} (reliability {reliability}/10) — set by an analyst decision on this "
            f"observable; of {analyzers_considered} analyzers that ran, {supporting_count} agree, "
            f"{contradicting_count} disagree, {silent_count} silent"
        )
    # Count-neutral wording ("1 supporting", not "1 support it"), reusing the same three words as
    # the payload keys and the prompt's narration rule so the model has one vocabulary, not two.
    return (
        f"{bucket} (reliability {reliability}/10) — {analyzers_considered} analyzers ran: "
        f"{supporting_count} supporting, {contradicting_count} contradicting, {silent_count} silent"
    )


def _partition_analyzers(
    job: Job, evaluation: str | None
) -> tuple[list[AnalyzerVerdict], list[AnalyzerVerdict], list[str]]:
    """Split the analyzers that ran into supporting / contradicting / silent.

    Attribution goes through `data_model_object_id` rather than the report's `data_model`
    GenericForeignKey: the FK resolves lazily, one query per report, while the whole set is
    already available in the single queryset `get_analyzers_data_models()` runs. Evidence is
    ordered by reliability so the caps in `evaluate_job` keep the strongest evidence.
    """
    data_models_by_pk = {data_model.pk: data_model for data_model in job.get_analyzers_data_models()}
    supporting, contradicting, silent = [], [], []
    for report in job.analyzerreports.all():
        data_model = data_models_by_pk.get(report.data_model_object_id)
        if data_model is None or not data_model.evaluation:
            # Ran but expressed no opinion: a blocklist miss, a timeout, or a missing API key.
            silent.append(report.config.name)
            continue
        verdict = AnalyzerVerdict(
            name=report.config.name,
            evaluation=data_model.evaluation,
            reliability=data_model.reliability,
        )
        if data_model.evaluation == evaluation:
            supporting.append(verdict)
        else:
            contradicting.append(verdict)
    supporting.sort(key=lambda item: item.reliability, reverse=True)
    contradicting.sort(key=lambda item: item.reliability, reverse=True)
    return supporting, contradicting, silent


def evaluate_job(job: Job) -> JobEvaluation:
    """Read the reconciled verdict of `job` and the per-analyzer evidence behind it.

    The headline is recomputed live with the platform's own `EvaluationEngineModule` instead of
    reading `job.data_model`: the engine modules run asynchronously *after* the pipeline saves a
    transient, un-reconciled merge (`engines_manager/models.py`), so the stored scalar can be
    wrong for a window. `EvaluationEngineModule.run` is a pure read of the same two sources, so
    recomputing removes that race by construction and guarantees the chatbot cannot diverge from
    the badge.

    Pure function: no writes, and no `Job` lookup — `job` must already be scoped to the
    requesting user by the caller.
    """
    if job.analyzable.classification == Classification.GENERIC.value:
        # The engine skips generic observables entirely and no DataModel class exists for them,
        # so `get_analyzers_data_models()` would raise NotImplementedError here.
        no_evaluation = DataModelVerdictBuckets.NO_EVALUATION.value
        return JobEvaluation(
            bucket=no_evaluation,
            evaluation=None,
            reliability=0,
            headline=f"{no_evaluation} — {REASON_GENERIC}",
            reason=REASON_GENERIC,
        )

    headline = EvaluationEngineModule(job).run() or {}
    evaluation = headline.get("evaluation")
    # The engine averages reliability into a float and then stores it through an integer column:
    # `merge()` assigns it and saves, and Django's IntegerField.get_prep_value does `int(value)`,
    # which TRUNCATES. Truncating here too is what makes the chatbot say the same word as the
    # badge — rounding would turn a stored 5 (Avg 5.5 -> suspicious) into 6 (malicious).
    reliability = int(headline.get("reliability") or 0)
    bucket = classify(evaluation, reliability)
    # Reported as a flag only. The engine resolves user events with the job owner's visibility
    # (`Job.get_user_events_data_model`), so surfacing any detail of the event itself — author,
    # reason, tags — could expose data the *requesting* user cannot see. The flag adds nothing
    # beyond the verdict value, which is already public to anyone who can see the job.
    analyst_override = job.get_user_events_data_model().exists()

    supporting, contradicting, silent = _partition_analyzers(job, evaluation)
    reason = REASON_NO_EVALUATION if evaluation is None else None
    analyzers_considered = len(supporting) + len(contradicting) + len(silent)
    return JobEvaluation(
        bucket=bucket,
        evaluation=evaluation,
        reliability=reliability,
        headline=_format_headline(
            bucket,
            reliability,
            len(supporting),
            len(contradicting),
            len(silent),
            analyzers_considered,
            analyst_override,
            reason,
        ),
        analyst_override=analyst_override,
        reason=reason,
        supporting=supporting[:MAX_EVIDENCE_ANALYZERS],
        contradicting=contradicting[:MAX_EVIDENCE_ANALYZERS],
        silent=silent[:MAX_SILENT_ANALYZERS],
        silent_count=len(silent),
        analyzers_considered=analyzers_considered,
    )

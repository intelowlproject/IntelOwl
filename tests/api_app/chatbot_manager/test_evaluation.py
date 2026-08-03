# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Unit tests for the chatbot's job-verdict reader.

The reader never invokes the LLM and never queries Job, so these tests seed DataModels
directly and assert the reader agrees with the platform's own reconciliation.
"""

from uuid import uuid4

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.chatbot_manager.evaluation import (
    MAX_EVIDENCE_ANALYZERS,
    REASON_GENERIC,
    REASON_NO_EVALUATION,
    evaluate_job,
)
from api_app.choices import TLP, Classification
from api_app.data_model_manager.enums import DataModelEvaluations, DataModelVerdictBuckets
from api_app.data_model_manager.models import DomainDataModel
from api_app.engines_manager.engines.evaluation import EvaluationEngineModule
from api_app.models import Job
from api_app.user_events_manager.models import UserAnalyzableEvent
from certego_saas.apps.user.models import User


class JobEvaluationTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_verdict_user")
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="verdict.example.com", classification=Classification.DOMAIN
        )
        self.job = self._make_job(self.analyzable)
        # The seeded DB ships hundreds of configs; a slice gives distinct (job, config) pairs.
        self.configs = list(AnalyzerConfig.objects.all()[:15])

    def tearDown(self):
        Job.objects.filter(user=self.user).delete()
        UserAnalyzableEvent.objects.filter(user=self.user).delete()

    def _make_job(self, analyzable):
        return Job.objects.create(
            user=self.user,
            analyzable=analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.CLEAR.value,
        )

    @staticmethod
    def _data_model(evaluation, reliability):
        return DomainDataModel.objects.create(evaluation=evaluation, reliability=reliability)

    def _add_report(self, config, data_model=None, job=None):
        report = AnalyzerReport.objects.create(
            report={},
            job=job or self.job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid4()),
            parameters={},
        )
        if data_model is not None:
            # GenericForeignKey assignment sets content type + object id in one go.
            report.data_model = data_model
            report.save()
        return report

    def test_generic_observable_reports_no_evaluation_honestly(self):
        """GENERIC has no DataModel class at all — the reader must say so, not fabricate."""
        generic, _ = Analyzable.objects.get_or_create(
            name="some free text", classification=Classification.GENERIC
        )
        result = evaluate_job(self._make_job(generic))
        self.assertEqual(result.bucket, DataModelVerdictBuckets.NO_EVALUATION.value)
        self.assertEqual(result.reason, REASON_GENERIC)
        self.assertIsNone(result.evaluation)
        self.assertEqual(result.supporting, [])

    def test_no_data_models_reports_no_evaluation_and_lists_silent(self):
        for config in self.configs[:3]:
            self._add_report(config)
        result = evaluate_job(self.job)
        self.assertEqual(result.bucket, DataModelVerdictBuckets.NO_EVALUATION.value)
        self.assertEqual(result.reason, REASON_NO_EVALUATION)
        self.assertEqual(result.silent_count, 3)
        self.assertEqual(sorted(result.silent), sorted(c.name for c in self.configs[:3]))
        self.assertEqual(result.analyzers_considered, 3)

    def test_malicious_verdict_partitions_the_evidence(self):
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        self._add_report(self.configs[1], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        self._add_report(self.configs[2], self._data_model(DataModelEvaluations.TRUSTED.value, 4))
        self._add_report(self.configs[3])  # ran, no data model -> silent
        result = evaluate_job(self.job)
        self.assertEqual(result.bucket, DataModelVerdictBuckets.MALICIOUS.value)
        self.assertEqual(result.evaluation, DataModelEvaluations.MALICIOUS.value)
        self.assertEqual(result.reliability, 8)
        # assertCountEqual: the two supporting analyzers tie on reliability and `analyzerreports`
        # carries no explicit ordering, so their relative order is not guaranteed by the DB.
        self.assertCountEqual(
            [v.name for v in result.supporting], [self.configs[0].name, self.configs[1].name]
        )
        self.assertEqual([v.name for v in result.contradicting], [self.configs[2].name])
        self.assertEqual(result.silent, [self.configs[3].name])
        self.assertEqual(result.analyzers_considered, 4)
        self.assertFalse(result.analyst_override)

    def test_headline_states_all_three_counts_including_zero_silence(self):
        """The headline must be self-contained: supporting, contradicting AND silent counts.

        This is not cosmetic. A live smoke against qwen2.5:3b showed that a headline reporting only
        "N of M analyzers support it" makes the model infer the remaining M-N analyzers all
        disagree, and then state there were no silent ones — the opposite of the honest-absence
        reporting this module exists to provide. The silent count is stated even when it is 0.
        """
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        self._add_report(self.configs[1], self._data_model(DataModelEvaluations.TRUSTED.value, 4))
        self._add_report(self.configs[2])  # ran, no data model -> silent
        headline = evaluate_job(self.job).headline
        self.assertIn("3 analyzers ran", headline)
        self.assertIn("1 supporting", headline)
        self.assertIn("1 contradicting", headline)
        self.assertIn("1 silent", headline)

    def test_headline_equals_the_platform_reconciliation(self):
        """The verdict must be the engine's verdict — never a chatbot-side recomputation."""
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 7))
        self._add_report(self.configs[1], self._data_model(DataModelEvaluations.MALICIOUS.value, 6))
        engine_result = EvaluationEngineModule(self.job).run()
        result = evaluate_job(self.job)
        self.assertEqual(result.evaluation, engine_result["evaluation"])
        self.assertEqual(result.reliability, int(engine_result["reliability"]))

    def test_reliability_matches_the_value_the_engine_persists(self):
        """Avg(5, 6) = 5.5 and the engine TRUNCATES it to 5 -> suspicious, not malicious.

        `merge()` assigns the float and saves; Django's IntegerField.get_prep_value does `int(v)`
        (truncation, not rounding), so the badge shows 5. This test replays exactly what
        `execute_engine_module` does and pins the reader to the persisted value: rounding here
        would make the chatbot say "malicious" while the badge says "suspicious", the one thing
        the design forbids.
        """
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 5))
        self._add_report(self.configs[1], self._data_model(DataModelEvaluations.MALICIOUS.value, 6))
        stored = DomainDataModel.objects.create()
        stored.merge(EvaluationEngineModule(self.job).run(), append=False)
        stored.refresh_from_db()
        result = evaluate_job(self.job)
        self.assertEqual(stored.reliability, 5)
        self.assertEqual(result.reliability, stored.reliability)
        self.assertEqual(result.bucket, DataModelVerdictBuckets.SUSPICIOUS.value)

    def test_stale_job_scalar_is_ignored_the_race_case(self):
        """The engine runs async, so `job.data_model` can hold a stale/absent verdict.

        Here the job is still RUNNING and its scalar says `trusted` while the analyzer DataModels
        say malicious: the reader must report malicious, because it recomputes from the same
        sources the engine uses instead of trusting the scalar.
        """
        self.job.status = Job.STATUSES.RUNNING
        self.job.data_model = self._data_model(DataModelEvaluations.TRUSTED.value, 9)
        self.job.save()
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        result = evaluate_job(self.job)
        self.assertEqual(result.bucket, DataModelVerdictBuckets.MALICIOUS.value)
        self.assertEqual(result.reliability, 8)
        self.assertFalse(result.analyst_override)

    def test_malicious_below_the_floor_is_suspicious(self):
        """Boundary: reliability 5 is under MALICIOUS_RELIABILITY_FLOOR (6)."""
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 5))
        self.assertEqual(evaluate_job(self.job).bucket, DataModelVerdictBuckets.SUSPICIOUS.value)

    def test_analyst_event_wins_and_is_surfaced(self):
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        UserAnalyzableEvent.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            data_model=self._data_model(DataModelEvaluations.TRUSTED.value, 9),
        )
        result = evaluate_job(self.job)
        self.assertEqual(result.bucket, DataModelVerdictBuckets.TRUSTED.value)
        self.assertTrue(result.analyst_override)
        self.assertIn("analyst", result.headline)
        # The override headline must still carry the counts: a headline that omits them is what
        # made the model assert there were no silent analyzers (see the smoke report).
        self.assertIn("0 agree", result.headline)
        self.assertIn("1 disagree", result.headline)
        self.assertIn("0 silent", result.headline)
        # the disagreeing analyzer is still shown, so the chatbot never hides the conflict
        self.assertEqual([v.name for v in result.contradicting], [self.configs[0].name])

    def test_evidence_lists_are_capped(self):
        for config in self.configs[:12]:
            self._add_report(config, self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        result = evaluate_job(self.job)
        self.assertEqual(len(result.supporting), MAX_EVIDENCE_ANALYZERS)
        self.assertEqual(result.analyzers_considered, 12)

    def test_reader_writes_nothing(self):
        """Pure read: the live recompute must not persist a data model on the job."""
        self._add_report(self.configs[0], self._data_model(DataModelEvaluations.MALICIOUS.value, 8))
        evaluate_job(self.job)
        self.job.refresh_from_db()
        self.assertIsNone(self.job.data_model_object_id)

from logging import getLogger
from typing import Dict, List

from api_app.data_model_manager.enums import DataModelEvaluations
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class DataModel(Visualizer):
    def get_eval_list(self, eval, color, icon, analyzers_datamodels):
        disable_element = not len(analyzers_datamodels)
        return self.VList(
            name=self.Base(
                value=eval,
                color=color if not disable_element else Visualizer.Color.TRANSPARENT,
                icon=icon,
                disable=False,
            ),
            value=[
                self.Base(
                    value=analyzer_name[0],
                    disable=False,
                )
                for analyzer_name in analyzers_datamodels
            ],
            size=self.Size.S_2,
            disable=disable_element,
            start_open=True,
        )

    def get_base_data_list(self, name, values_list):
        disable_element = not len(values_list)
        return self.VList(
            name=self.Base(value=name, disable=False),
            value=values_list,
            disable=disable_element,
            start_open=True,
        )

    def run(self) -> List[Dict]:
        trusted_datamodels = []
        clean_datamodels = []
        suspicious_datamodels = []
        malicious_datamodels = []
        noeval_datamodels = []

        for analyzer_report in self.analyzer_reports():
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            datamodel_class = analyzer_report.get_data_model_class(analyzer_report.job)
            datamodel = datamodel_class.objects.filter(
                analyzers_report=analyzer_report.pk
            ).first()
            if datamodel:
                logger.debug(f"{printable_analyzer_name}, {datamodel}")

                evaluation = ""
                if datamodel.evaluation:
                    evaluation = datamodel.evaluation.value

                if evaluation == DataModelEvaluations.TRUSTED:
                    trusted_datamodels.append((printable_analyzer_name, datamodel))
                elif evaluation == DataModelEvaluations.CLEAN:
                    clean_datamodels.append((printable_analyzer_name, datamodel))
                elif evaluation == DataModelEvaluations.SUSPICIOUS:
                    suspicious_datamodels.append((printable_analyzer_name, datamodel))
                elif evaluation == DataModelEvaluations.MALICIOUS:
                    malicious_datamodels.append((printable_analyzer_name, datamodel))
                else:
                    noeval_datamodels.append((printable_analyzer_name, datamodel))

        evals_vlists = []
        for evaluation, color, icon, eval_datamodels in [
            (
                "no evaluation",
                Visualizer.Color.SECONDARY,
                Visualizer.Icon.INFO,
                noeval_datamodels,
            ),
            (
                DataModelEvaluations.CLEAN.value,
                Visualizer.Color.SUCCESS,
                Visualizer.Icon.LIKE,
                clean_datamodels,
            ),
            (
                DataModelEvaluations.TRUSTED.value,
                Visualizer.Color.SUCCESS,
                Visualizer.Icon.LIKE,
                trusted_datamodels,
            ),
            (
                DataModelEvaluations.SUSPICIOUS.value,
                Visualizer.Color.WARNING,
                Visualizer.Icon.WARNING,
                suspicious_datamodels,
            ),
            (
                DataModelEvaluations.MALICIOUS.value,
                Visualizer.Color.DANGER,
                Visualizer.Icon.MALWARE,
                malicious_datamodels,
            ),
        ]:
            evals_vlists.append(
                self.get_eval_list(evaluation, color, icon, eval_datamodels)
            )

        datamodels = (
            noeval_datamodels
            + trusted_datamodels
            + clean_datamodels
            + suspicious_datamodels
            + malicious_datamodels
        )
        related_threats = []
        external_references = []
        malware_families = []
        tags = []

        for datamodel in datamodels:
            related_threats.extend(datamodel[1].related_threats)
            external_references.extend(datamodel[1].external_references)
            if datamodel[1].malware_family:
                malware_families.append(datamodel[1].malware_family)
            if datamodel[1].tags:
                tags.extend(datamodel[1].tags)

        related_threats = list(set(related_threats))
        external_references = list(set(external_references))
        malware_families = list(set(malware_families))
        tags = list(set(tags))

        base_data_vlists = []
        for name, values_list in [
            ("Tags", tags),
            ("Related threats", related_threats),
            ("Malware families", malware_families),
            ("External references", external_references),
        ]:
            base_data_vlists.append(self.get_base_data_list(name, values_list))

        page = self.Page(name="DataModel")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=evals_vlists),
            )
        )

        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=base_data_vlists),
            )
        )

        return [page.to_dict()]

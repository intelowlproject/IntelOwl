from logging import getLogger
from typing import Dict, List

from api_app.data_model_manager.enums import DataModelEvaluations
from api_app.data_model_manager.models import (
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableTableColumnSize

logger = getLogger(__name__)


class DataModel(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("get_eval_list")
    def get_eval_list(self, evaluation, color, icon, data_models):
        disable_element = not bool(data_models)
        return self.VList(
            name=self.Base(
                value=evaluation,
                color=color if not disable_element else Visualizer.Color.TRANSPARENT,
                icon=icon,
                disable=False,
            ),
            value=[
                self.Base(
                    value=data_model.analyzers_report.all().first().config.name,
                    disable=False,
                )
                for data_model in data_models
            ],
            size=self.Size.S_2,
            disable=disable_element,
            start_open=True,
        )

    @visualizable_error_handler_with_params("get_base_data_list")
    def get_base_data_list(self, name, values_list):
        disable_element = not bool(values_list)
        return self.VList(
            name=self.Base(value=name, disable=False),
            value=values_list,
            disable=disable_element,
            start_open=True,
        )

    @visualizable_error_handler_with_params("get_field")
    def get_field(self, field, data_models):
        for data_model in data_models:
            value = getattr(data_model, field, None)
            if value:
                return Visualizer.Title(
                    title=Visualizer.Base(value=field.replace("_", " "), disable=False),
                    value=Visualizer.Base(
                        value=value,
                        disable=False,
                    ),
                    disable=False,
                )

        return Visualizer.Title(
            title=Visualizer.Base(value=field.replace("_", " "), disable=True),
            value=Visualizer.Base(
                value="",
                disable=True,
            ),
            disable=True,
        )

    @visualizable_error_handler_with_params("get_resolutions")
    def get_resolutions(self, data_models):
        resolutions = []
        for data_model in data_models:
            if data_model.resolutions:
                resolutions.append(
                    self.VList(
                        name=self.Base(
                            value=data_model.analyzers_report.all().first().config.name,
                            disable=False,
                        ),
                        value=[
                            self.Base(
                                value=resolution,
                                disable=False,
                            )
                            for resolution in data_model.resolutions
                        ],
                        size=self.Size.S_2,
                        disable=False,
                        start_open=True,
                    )
                )
        return resolutions

    @visualizable_error_handler_with_params("get_pdns")
    def get_pdns(self, data_models):
        columns = [
            self.TableColumn(name="rrname", max_width=VisualizableTableColumnSize.S_300),
            self.TableColumn(name="rrtype", max_width=VisualizableTableColumnSize.S_50),
            self.TableColumn(name="rdata", max_width=VisualizableTableColumnSize.S_300),
            self.TableColumn(name="time_first", max_width=VisualizableTableColumnSize.S_100),
            self.TableColumn(name="time_last", max_width=VisualizableTableColumnSize.S_100),
            self.TableColumn(name="analyzer", max_width=VisualizableTableColumnSize.S_200),
        ]

        data = []
        for data_model in data_models:
            ietf_reports = data_model.ietf_report.all()
            for report in ietf_reports:
                data.append(
                    {
                        "rrname": self.Base(
                            value=report.rrname,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "rrtype": self.Base(
                            value=report.rrtype,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "rdata": self.VList(
                            value=[
                                self.Base(
                                    value=rdata,
                                    color=self.Color.TRANSPARENT,
                                    disable=False,
                                )
                                for rdata in report.rdata
                            ],
                            disable=False,
                        ),
                        "time_first": self.Base(
                            value=report.time_first.strftime("%Y-%m-%d %H:%M:%S"),
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "time_last": self.Base(
                            value=report.time_last.strftime("%Y-%m-%d %H:%M:%S"),
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "analyzer": self.Base(
                            value=data_model.analyzers_report.all().first().config.name,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                    }
                )

        return self.Table(
            columns=columns,
            data=data,
            size=Visualizer.Size.S_ALL,
            page_size=10,
            sort_by_id="last_view",
            sort_by_desc=True,
        )

    @visualizable_error_handler_with_params("get_signatures")
    def get_signatures(self, data_models):
        columns = [
            self.TableColumn(name="provider", max_width=VisualizableTableColumnSize.S_100),
            self.TableColumn(name="url", max_width=VisualizableTableColumnSize.S_300),
            self.TableColumn(name="score", max_width=VisualizableTableColumnSize.S_50),
            self.TableColumn(name="analyzer", max_width=VisualizableTableColumnSize.S_100),
        ]

        data = []
        for data_model in data_models:
            signatures = data_model.signatures.all()
            for signature in signatures:
                data.append(
                    {
                        "provider": self.Base(
                            value=signature.provider,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "url": self.Base(
                            value=(signature.url if signature.url else "No url available"),
                            link=signature.url,
                            color=self.Color.TRANSPARENT,
                            disable=not signature.url,
                        ),
                        "score": self.Base(
                            value=signature.score,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                        "analyzer": self.Base(
                            value=data_model.analyzers_report.all().first().config.name,
                            color=self.Color.TRANSPARENT,
                            disable=False,
                        ),
                    }
                )

        return self.Table(
            columns=columns,
            data=data,
            size=Visualizer.Size.S_ALL,
            page_size=10,
            sort_by_id="provider",
        )

    def get_domain_data_elements(self, page, data_models):
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=self.get_resolutions(data_models)),
            )
        )

        page.add_level(
            self.Level(
                position=4,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=[self.get_field("rank", data_models)]),
            )
        )

        page.add_level(
            self.Level(
                position=5,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=[self.get_pdns(data_models)]),
            )
        )

    def get_ip_data_elements(self, page, data_models):
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=self.get_resolutions(data_models)),
            )
        )

        page.add_level(
            self.Level(
                position=4,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(
                    value=[
                        self.get_field(field, data_models)
                        for field in [
                            "asn",
                            "asn_rank",
                            "org_name",
                            "country_code",
                            "registered_country_code",
                            "isp",
                        ]
                    ]
                ),
            )
        )

        page.add_level(
            self.Level(
                position=5,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=[self.get_pdns(data_models)]),
            )
        )

    def get_file_data_elements(self, page, data_models):
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=[self.get_signatures(data_models)]),
            )
        )

    def run(self) -> List[Dict]:
        trusted_data_models = []
        clean_data_models = []
        suspicious_data_models = []
        malicious_data_models = []
        noeval_data_models = []
        data_models = self.get_data_models()

        for data_model in data_models:
            printable_analyzer_name = data_model.analyzers_report.all().first().config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name}, {data_model}")

            evaluation = data_model.evaluation or ""
            reliability = data_model.reliability

            if evaluation == DataModelEvaluations.TRUSTED.value:
                if reliability >= 8:
                    trusted_data_models.append(data_model)
                else:
                    clean_data_models.append(data_model)
            elif evaluation == DataModelEvaluations.MALICIOUS.value:
                if reliability >= 6:
                    malicious_data_models.append(data_model)
                else:
                    suspicious_data_models.append(data_model)
            else:
                noeval_data_models.append(data_model)

        evals_vlists = []
        for evaluation, color, icon, eval_data_models in [
            (
                "no evaluation",
                Visualizer.Color.SECONDARY,
                Visualizer.Icon.INFO,
                noeval_data_models,
            ),
            (
                "clean",
                Visualizer.Color.SUCCESS,
                Visualizer.Icon.LIKE,
                clean_data_models,
            ),
            (
                DataModelEvaluations.TRUSTED.value,
                Visualizer.Color.SUCCESS,
                Visualizer.Icon.LIKE,
                trusted_data_models,
            ),
            (
                "suspicious",
                Visualizer.Color.WARNING,
                Visualizer.Icon.WARNING,
                suspicious_data_models,
            ),
            (
                DataModelEvaluations.MALICIOUS.value,
                Visualizer.Color.DANGER,
                Visualizer.Icon.MALWARE,
                malicious_data_models,
            ),
        ]:
            evals_vlists.append(self.get_eval_list(evaluation, color, icon, eval_data_models))

        related_threats = []
        external_references = []
        malware_families = []
        tags = []

        for data_model in data_models:
            related_threats.extend(data_model.related_threats)
            external_references.extend(data_model.external_references)
            if data_model.malware_family:
                malware_families.append(data_model.malware_family)
            if data_model.tags:
                tags.extend(data_model.tags)

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
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=evals_vlists),
            )
        )

        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=base_data_vlists),
            )
        )

        data_model_class = self._job.analyzable.get_data_model_class()
        if data_model_class == DomainDataModel:
            self.get_domain_data_elements(page, data_models)
        elif data_model_class == IPDataModel:
            self.get_ip_data_elements(page, data_models)
        elif data_model_class == FileDataModel:
            self.get_file_data_elements(page, data_models)

        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)

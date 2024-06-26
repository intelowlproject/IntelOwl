from typing import Dict, List

from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableTableColumnSize
from api_app.visualizers_manager.visualizers.passive_dns.analyzer_extractor import (
    PDNSReport,
)


@visualizable_error_handler_with_params("pdns_table")
def pdns_table(
    raw_pdns_data: List[PDNSReport], table_columns: List[Visualizer.TableColumn]
) -> VisualizableObject:
    visualizable_reports = []
    for raw_report in raw_pdns_data:
        visualizable_reports.append(__visualize_report(raw_report))

    return [
        Visualizer.Table(
            data=visualizable_reports,
            columns=table_columns,
            size=Visualizer.Size.S_ALL,
            page_size=10,
            sort_by_id="last_view",
            sort_by_desc=True,
        )
    ]


def __visualize_report(raw_report: PDNSReport) -> Dict[str, VisualizableObject]:
    visualizable_row = {
        "last_view": Visualizer.Base(
            value=raw_report.last_view,
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
        ),
        "first_view": Visualizer.Base(
            value=raw_report.first_view,
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
        ),
        "rrtype": Visualizer.Base(
            value=raw_report.rrtype.upper(),
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
        ),
        "rrname": Visualizer.Base(
            value=raw_report.rrname,
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
        ),
        "source": Visualizer.Base(
            value=raw_report.source,
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
            description=raw_report.source_description,
        ),
    }
    if isinstance(raw_report.rdata, list):
        visualizable_row.update(
            {
                "rdata": Visualizer.VList(
                    value=[
                        Visualizer.Base(
                            value=data,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                        for data in raw_report.rdata
                    ],
                    disable=not raw_report.rdata,
                ),
            }
        )
    else:
        visualizable_row.update(
            {
                "rdata": Visualizer.Base(
                    value=raw_report.rdata,
                    color=Visualizer.Color.TRANSPARENT,
                    disable=False,
                )
            }
        )
    return visualizable_row


def standard_table_columns() -> List[Visualizer.TableColumn]:
    return [
        Visualizer.TableColumn(
            name="last_view",
            max_width=VisualizableTableColumnSize.S_100,
            description="""The last time that the unique tuple"
                 (rrname, rrtype, rdata) record has been seen by the passive DNS.""",
        ),
        Visualizer.TableColumn(
            name="first_view",
            max_width=VisualizableTableColumnSize.S_100,
            description="""The first time that the record / unique tuple
                 (rrname, rrtype, rdata) has been seen by the passive DNS.""",
        ),
        Visualizer.TableColumn(
            name="rrname",
            max_width=VisualizableTableColumnSize.S_300,
            disable_sort_by=True,
            description="Name of the queried resource.",
        ),
        Visualizer.TableColumn(
            name="rrtype",
            max_width=VisualizableTableColumnSize.S_50,
            disable_sort_by=True,
            description="Record type as seen by the passive DNS.",
        ),
        Visualizer.TableColumn(
            name="rdata",
            max_width=VisualizableTableColumnSize.S_300,
            disable_sort_by=True,
            description="Resource records of the queried resource.",
        ),
        Visualizer.TableColumn(
            name="source",
            max_width=VisualizableTableColumnSize.S_200,
            disable_sort_by=True,
            description="Source that reported the passive DNS data.",
        ),
    ]

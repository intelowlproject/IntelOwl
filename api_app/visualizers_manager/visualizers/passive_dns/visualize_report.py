from api_app.visualizers_manager.classes import Visualizer


def visualize_report(report):
    obj = {}
    source_description = report.pop("source_description", "")
    for [key, value] in report.items():
        if key == "rrtype":
            obj.update(
                {
                    key: Visualizer.Base(
                        value=value.upper(),
                        color=Visualizer.Color.TRANSPARENT,
                        disable=False,
                    )
                }
            )
        elif key == "rdata":
            if isinstance(value, list):
                obj.update(
                    {
                        "rdata": Visualizer.VList(
                            value=[
                                Visualizer.Base(
                                    value=data,
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
                                )
                                for data in value
                            ],
                            disable=not value,
                        ),
                    }
                )
            else:
                obj.update(
                    {
                        "rdata": Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
        elif key == "source":
            obj.update(
                {
                    key: Visualizer.Base(
                        value=value,
                        color=Visualizer.Color.TRANSPARENT,
                        disable=False,
                        description=source_description,
                    )
                }
            )
        elif key in ["rrname", "last_view", "first_view"]:
            obj.update(
                {
                    key: Visualizer.Base(
                        value=value,
                        color=Visualizer.Color.TRANSPARENT,
                        disable=False,
                    )
                }
            )
    return obj

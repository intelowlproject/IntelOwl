# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer


class DarkSearchQuery(ObservableAnalyzer):
    name: str = "DarkSearchQuery"

    def set_config(self, config_params):
        self.num_pages = int(config_params.get("pages", 5))
        self.proxies = config_params.get("proxies", None)

    def run(self):
        from darksearch import Client

        c = Client(proxies=self.proxies)
        responses = c.search(self.observable_name, pages=self.num_pages)
        report = {
            "total": responses[0]["total"],
            "total_pages": responses[0]["last_page"],
            "requested_pages": self.num_pages,
            "data": [],
        }
        for resp in responses:
            report["data"].extend(resp["data"])

        return report

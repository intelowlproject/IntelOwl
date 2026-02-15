# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.enums import (
    VisualizableIcon,
    VisualizableTableColumnSize,
)

logger = getLogger(__name__)


class CrawlResults(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        pages = []

        analyzer_reports = self.get_analyzer_reports().filter(
            config__name="UrlScan_Submit_Result"
        )

        for analyzer_report in analyzer_reports:
            if (
                analyzer_report.status == ReportStatus.SUCCESS
                and analyzer_report.report
            ):
                page = self._create_urlscan_page(analyzer_report.report)
                pages.append(page.to_dict())

        if not pages:
            page = self._create_empty_page()
            pages.append(page.to_dict())

        return pages

    def _create_empty_page(self):
        page = self.Page(name="Crawl Results")

        level = self.Level(
            position=0,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(
                value=[
                    self.Base(
                        value="No crawl results available",
                        color=self.Color.WARNING,
                        disable=True,
                    )
                ]
            ),
        )
        page.add_level(level)
        return page

    def _create_urlscan_page(self, report_data):
        page = self.Page(name="URLScan.io Results")

        page.add_level(self._create_header_level(report_data))

        redirect_level = self._create_redirect_chain_level(report_data)
        if redirect_level:
            page.add_level(redirect_level)

        requests_level = self._create_network_requests_level(report_data)
        if requests_level:
            page.add_level(requests_level)

        links_level = self._create_links_level(report_data)
        if links_level:
            page.add_level(links_level)

        hosting_level = self._create_hosting_level(report_data)
        if hosting_level:
            page.add_level(hosting_level)

        return page

    def _create_header_level(self, report_data):
        elements = []

        result_url = report_data.get("task", {}).get("reportURL", "")
        screenshot_url = report_data.get("task", {}).get("screenshotURL", "")

        elements.append(
            self.Title(
                title=self.Base(
                    value="URLScan.io",
                    link=result_url,
                    icon=VisualizableIcon.MAGNIFYING_GLASS,
                    bold=True,
                ),
                value=self.Base(
                    value="Web Crawl Analysis",
                    disable=False,
                ),
                disable=False,
            )
        )

        if screenshot_url:
            elements.append(
                self.Base(
                    value="View Screenshot",
                    link=screenshot_url,
                    icon=VisualizableIcon.INBOX,
                    color=self.Color.PRIMARY,
                    disable=False,
                )
            )

        return self.Level(
            position=0,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(value=elements),
        )

    def _create_redirect_chain_level(self, report_data):
        data_section = report_data.get("data", {})
        requests = data_section.get("requests", [])

        if not requests:
            return None

        redirect_chain = []
        for req in requests:
            response = req.get("response", {})
            if response.get("status") in [301, 302, 303, 307, 308]:
                redirect_chain.append(
                    {
                        "url": req.get("request", {}).get("url", ""),
                        "status": response.get("status", ""),
                        "ip": response.get("response", {}).get("remoteIPAddress", ""),
                    }
                )

        if not redirect_chain:
            return None

        table_data = []
        for idx, redirect in enumerate(redirect_chain):
            table_data.append(
                {
                    "step": self.Base(value=str(idx + 1), disable=False),
                    "url": self.Base(
                        value=redirect["url"],
                        link=redirect["url"],
                        disable=False,
                        copy_text=redirect["url"],
                    ),
                    "status": self.Base(
                        value=str(redirect["status"]),
                        color=(
                            self.Color.WARNING
                            if redirect["status"] >= 300
                            else self.Color.SUCCESS
                        ),
                        disable=False,
                    ),
                    "ip": self.Base(value=redirect["ip"], disable=False),
                }
            )

        table = self.Table(
            columns=[
                self.TableColumn(
                    name="step", max_width=VisualizableTableColumnSize.S_50
                ),
                self.TableColumn(
                    name="url", max_width=VisualizableTableColumnSize.S_300
                ),
                self.TableColumn(
                    name="status", max_width=VisualizableTableColumnSize.S_100
                ),
                self.TableColumn(
                    name="ip", max_width=VisualizableTableColumnSize.S_200
                ),
            ],
            data=table_data,
            page_size=10,
        )

        vlist = self.VList(
            name=self.Base(value="Redirect Chain", bold=True, disable=False),
            value=[table],
            start_open=True,
            disable=False,
        )

        return self.Level(
            position=1,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(value=[vlist]),
        )

    def _create_network_requests_level(self, report_data):
        data_section = report_data.get("data", {})
        requests = data_section.get("requests", [])

        if not requests:
            return None

        xhr_requests = []
        ws_requests = []
        js_requests = []

        for req in requests:
            request_data = req.get("request", {})
            request_details = request_data.get("request", {})
            request_type = request_data.get("type", "")
            url = request_details.get("url", "")

            if request_type in ("XHR", "Fetch"):
                xhr_requests.append(url)
            elif request_type == "WebSocket":
                ws_requests.append(url)
            elif request_type == "Script" or url.endswith(".js"):
                js_requests.append(url)

        elements = []

        if xhr_requests:
            xhr_items = [
                self.Base(value=url, link=url, disable=False, copy_text=url)
                for url in xhr_requests[:20]
            ]
            xhr_list = self.VList(
                name=self.Base(value="XHR/Fetch Requests", bold=True, disable=False),
                value=xhr_items,
                size=self.Size.S_AUTO,
                start_open=False,
                disable=False,
                max_elements_number=20,
            )
            elements.append(xhr_list)

        if ws_requests:
            ws_items = [
                self.Base(value=url, link=url, disable=False, copy_text=url)
                for url in ws_requests[:20]
            ]
            ws_list = self.VList(
                name=self.Base(value="WebSocket Connections", bold=True, disable=False),
                value=ws_items,
                size=self.Size.S_AUTO,
                start_open=False,
                disable=False,
                max_elements_number=20,
            )
            elements.append(ws_list)

        if js_requests:
            js_items = [
                self.Base(value=url, link=url, disable=False, copy_text=url)
                for url in js_requests[:20]
            ]
            js_list = self.VList(
                name=self.Base(value="JavaScript Files", bold=True, disable=False),
                value=js_items,
                size=self.Size.S_AUTO,
                start_open=False,
                disable=False,
                max_elements_number=20,
            )
            elements.append(js_list)

        if not elements:
            return None

        return self.Level(
            position=2,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(value=elements),
        )

    def _create_links_level(self, report_data):
        data_section = report_data.get("data", {})
        links = data_section.get("links", [])

        if not links:
            return None

        table_data = []
        for link in links[:50]:
            href = link.get("href", "")
            text = link.get("text", "")

            table_data.append(
                {
                    "url": self.Base(
                        value=href,
                        link=href,
                        disable=False,
                        copy_text=href,
                    ),
                    "text": self.Base(value=text[:100], disable=False),
                }
            )

        if not table_data:
            return None

        table = self.Table(
            columns=[
                self.TableColumn(
                    name="url", max_width=VisualizableTableColumnSize.S_300
                ),
                self.TableColumn(
                    name="text", max_width=VisualizableTableColumnSize.S_250
                ),
            ],
            data=table_data,
            page_size=10,
        )

        vlist = self.VList(
            name=self.Base(
                value=f"Page Links ({len(links)} total)",
                bold=True,
                disable=False,
            ),
            value=[table],
            start_open=False,
            disable=False,
        )

        return self.Level(
            position=3,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(value=[vlist]),
        )

    def _create_hosting_level(self, report_data):
        page_data = report_data.get("page", {})

        if not page_data:
            return None

        elements = []

        ip = page_data.get("ip", "")
        if ip:
            elements.append(
                self.Title(
                    title=self.Base(value="IP Address", bold=True, disable=False),
                    value=self.Base(value=ip, disable=False, copy_text=ip),
                    disable=False,
                )
            )

        country = page_data.get("country", "")
        if country:
            elements.append(
                self.Title(
                    title=self.Base(value="Country", bold=True, disable=False),
                    value=self.Base(value=country, disable=False),
                    disable=False,
                )
            )

        server = page_data.get("server", "")
        if server:
            elements.append(
                self.Title(
                    title=self.Base(value="Server", bold=True, disable=False),
                    value=self.Base(value=server, disable=False),
                    disable=False,
                )
            )

        asn = page_data.get("asn", "")
        asnname = page_data.get("asnname", "")
        if asn:
            asn_display = f"{asn} - {asnname}" if asnname else asn
            elements.append(
                self.Title(
                    title=self.Base(value="ASN", bold=True, disable=False),
                    value=self.Base(value=asn_display, disable=False),
                    disable=False,
                )
            )

        if not elements:
            return None

        vlist = self.VList(
            name=self.Base(value="Hosting Information", bold=True, disable=False),
            value=elements,
            start_open=True,
            disable=False,
        )

        return self.Level(
            position=4,
            size=self.LevelSize.S_5,
            horizontal_list=self.HList(value=[vlist]),
        )

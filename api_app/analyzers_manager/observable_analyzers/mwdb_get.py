# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import mwdblib

from api_app.analyzers_manager.classes import ObservableAnalyzer

logger = logging.getLogger(__name__)


class MWDBGet(ObservableAnalyzer):
    _api_key_name: str

    def run(self):
        mwdb = mwdblib.MWDB(api_key=self._api_key_name)

        result = {}
        try:
            file_info = mwdb.query_file(self.observable_name)
        except mwdblib.exc.ObjectNotFoundError:
            result["not_found"] = True
        except Exception as exc:
            logger.exception(exc)
            self.report.errors.append(str(exc))
            result["not_found"] = True
        else:
            result["data"] = file_info.data
            # this could fail due to non-existing attributes
            try:
                result["attributes"] = file_info.attributes
            except Exception as e:
                logger.warning(e, stack_info=True)
                self.report.errors.append(str(e))
            result["permalink"] = f"https://mwdb.cert.pl/file/{self.observable_name}"

        return result

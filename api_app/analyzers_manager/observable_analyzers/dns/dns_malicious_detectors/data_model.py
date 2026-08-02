# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


class MaliciousDetectorResponseDataModelMixin:
    """Emit a DataModel only on a real malicious hit.

    These analyzers map the constant ``$malicious -> evaluation`` in their
    ``mapping_data_model``, which writes ``evaluation = "malicious"`` unconditionally
    whenever a data model is created. So a clean lookup (``malicious: false``), a
    timeout, or a failure note would otherwise be stamped MALICIOUS. Gating creation
    on ``report["malicious"] is True`` makes a non-hit produce no data model (silent);
    it must never map a non-hit to trusted.
    """

    def _do_create_data_model(self) -> bool:
        return super()._do_create_data_model() and self.report.report.get("malicious") is True

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""These are the default responses"""


def malicious_detector_response(
    observable: str, malicious: bool, timeout: bool = False, note: str = None
) -> dict:
    """Standard response for malicious detector analyzers

    :param observable: observable analyzed
    :type observable: str
    :param malicious: tell if the observable is reported as malicious from analyzer
    :type malicious: bool
    :param timeout: set if the DNS query timed-out
    :type timeout bool
    :param note: additional note to add to the report, default to None
    :type note: str, optional
    :return:
    :rtype: dict
    """

    report = {"observable": observable, "malicious": malicious}

    if timeout:
        report["timeout"] = True
    if note:
        report["note"] = note

    return report


def dns_resolver_response(observable: str, resolutions: list = None, timeout: bool = False) -> dict:
    """Standard response for DNS resolver analyzers

    :param observable: observable analyzed
    :type observable: str
    :param resolutions: list of DNS resolutions, it is empty in case of no resolutions,
    default to None
    :type resolutions: list, optional
    :param timeout: set if the DNS query timed-out
    :type timeout bool
    :return:
    :rtype: dict
    """

    if not resolutions:
        resolutions = []

    report = {"observable": observable, "resolutions": resolutions}

    if timeout:
        report["timeout"] = True

    return report

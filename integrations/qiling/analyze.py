#!/usr/bin/env python3
import json
from argparse import ArgumentParser
from qiling import Qiling
from qiling.extensions.report import generate_report
import logging

BASE_PATH = "/opt/deploy"
logger = logging.getLogger(__name__)


class StringBuffer:
    def __init__(self):
        self.buffer = b""

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def readline(self, end=b"\n"):
        ret = b""
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)


def my_sandbox(file, ql_os, ql_arch, shellcode=False, profile=None):
    result = {}
    args = {}
    if profile:
        args["profile"] = f"{BASE_PATH}/profiles/{profile}"
    if shellcode:
        with open(file, "br") as f:
            args["shellcoder"] = f.read()
        args["ostype"] = ql_os
        args["archtype"] = ql_arch
    args["rootfs"] = f"{BASE_PATH}/rootfs/{ql_arch}_{ql_os}"
    # Std output is done to block the emulated software to print to standard output
    try:
        ql = Qiling(
            [file], **args, output="default", console=False, stdout=StringBuffer()
        )
        try:
            ql.run()
        except Exception as e:
            result["execution_error"] = str(e)
    except Exception as e:
        result["setup_error"] = str(e)
    else:
        result.update(generate_report(ql))
    finally:
        print(json.dumps(result))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("ql_os", type=str, choices=["linux", "windows", "freebsd"])
    parser.add_argument("ql_arch", type=str, choices=["x86", "x8664", "arm"])
    parser.add_argument("--shellcode", action="store_true")
    parser.add_argument("--profile", default=None, type=str)
    arguments = parser.parse_args()
    my_sandbox(**vars(arguments))

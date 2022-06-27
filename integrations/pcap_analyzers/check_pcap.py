# reference
# https://github.com/OISF/suricata/blob/master/python/suricata/sc/suricatasc.py
import argparse
import json
import os
from socket import AF_UNIX, socket


def check_pcap():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("filename", type=str)
        parser.add_argument("file_md5", type=str)
        parser.add_argument("verbose", type=bool)
        args = parser.parse_args()
        print(args.file_md5)
        print(args.filename)
        analysis_dir = f"/tmp/eve_{args.file_md5}"
        os.mkdir(analysis_dir)
        s = socket(AF_UNIX)
        s.connect("/tmp/suricata.socket")
        s.send(bytes(json.dumps({"version": "0.2"}), "iso-8859-1"))
        s.send(
            bytes(
                json.dumps(
                    {
                        "command": "pcap-file",
                        "arguments": {"output-dir": analysis_dir},
                        "filename": args.filename,
                    }
                )
                + "\n",
                "iso-8859-1",
            )
        )
        received = s.recv(1024).decode("iso-8859-1")
        print(received)
        # manage verbose
        print("here")
        # shutil.rmtree(analysis_dir)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    check_pcap()

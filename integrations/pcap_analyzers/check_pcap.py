# reference
# https://github.com/OISF/suricata/blob/master/python/suricata/sc/suricatasc.py
import argparse
import json
import logging
import os
import select
import time
from socket import AF_UNIX, socket

LOG_NAME = "check_pcap"

# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{LOG_NAME}")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/{LOG_NAME}.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/{LOG_NAME}_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)


class Suricata:
    def __init__(self):
        # connect to Suricata Socket
        self.s = socket(AF_UNIX)

    def check_pcap(self):
        try:
            parser = argparse.ArgumentParser()
            parser.add_argument("filename", type=str)
            parser.add_argument("file_md5", type=str)
            args = parser.parse_args()
            logger.info(
                f"received args: filename: {args.filename}, " f"md5: {args.file_md5}"
            )
            filename = str(args.filename)

            analysis_dir = f"/tmp/eve_{args.file_md5}"
            os.mkdir(analysis_dir, 0o777)
            # this analysis dir is removed in the interception function in app.py

            # this must be the same name chosen for the Suricata Socket
            self.s.connect("/tmp/suricata.socket")
            self.s.settimeout(10)

            logger.info(f"send version, md5 {args.file_md5}")
            self.s.send(bytes(json.dumps({"version": "0.2"}), "iso-8859-1"))
            logger.info(f"receiving result, md5 {args.file_md5}")
            ready = select.select([self.s], [], [], 600)
            if ready[0]:
                cmdret = self._json_recv()
            else:
                raise Exception(f"unable to get message, md5 {args.file_md5}")
            logger.info(f"result received: {cmdret}")
            if cmdret["return"] == "NOK":
                raise Exception(f"error: {cmdret['message']}, , md5 {args.file_md5}")

            # https://suricata.readthedocs.io/en/latest/unix-socket.html
            logger.info(f"send pcap file, md5 {args.file_md5}")
            cmdmsg = {
                "command": "pcap-file",
                "arguments": {"output-dir": analysis_dir, "filename": filename},
            }
            cmdstr = json.dumps(cmdmsg) + "\n"
            self.s.send(
                bytes(
                    cmdstr,
                    "iso-8859-1",
                )
            )
            logger.info(f"receiving result, md5 {args.file_md5}")
            ready = select.select([self.s], [], [], 600)
            if ready[0]:
                cmdret = self._json_recv()
            else:
                raise Exception(f"unable to get message, md5 {args.file_md5}")
            logger.info(f"result received: {cmdret}")

            # waiting for eve.json to be populated
            max_tries = 10
            polling_time = 1
            for try_ in range(max_tries):
                if os.path.exists(analysis_dir + "/eve.json"):
                    break
                time.sleep(polling_time)

            self.s.close()
        except Exception as e:
            logger.exception(e)

    def _json_recv(self):
        cmdret = None
        data = ""
        max_tries = 20
        for try_ in range(max_tries):
            received = self.s.recv(1024).decode("iso-8859-1")
            if not received:
                break
            data += received
            if data.endswith("\n"):
                cmdret = json.loads(data)
                break
            time.sleep(1)

        return cmdret


if __name__ == "__main__":
    Suricata().check_pcap()

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
        try:
            # connect to Suricata Socket
            self.s = socket(AF_UNIX)
            parser = argparse.ArgumentParser()
            parser.add_argument("filename", type=str)
            parser.add_argument("file_md5", type=str)
            parser.add_argument("job_id", type=str)
            parser.add_argument("--reload_rules", action="store_true")
            args = parser.parse_args()
            logger.info(
                f"received args: filename: {args.filename}, md5: {args.file_md5},"
                f" reload_rules {args.reload_rules}, job_id: {args.job_id}"
            )
            self.filename = str(args.filename)
            self.job_id = args.job_id
            self.md5 = args.file_md5
            self.reload_rules = args.reload_rules
            self.analysis_dir = f"/tmp/eve_{self.job_id}"
            self.eve_file = self.analysis_dir + "/eve.json"
            self.check_pcap()
        except Exception as e:
            logger.exception(e)

    def check_pcap(self):
        # this analysis dir is removed in the interception function in app.py
        os.mkdir(self.analysis_dir, 0o777)

        # this must be the same name chosen for the Suricata Socket
        self.s.connect("/tmp/suricata.socket")
        self.s.settimeout(10)

        self._send_command("version")

        if self.reload_rules:
            self._send_command("ruleset-reload-rules")
            self._send_command("ruleset-stats")
            self._send_command("ruleset-failed-rules")

        self._send_command(
            "pcap-file",
            arguments={"output-dir": self.analysis_dir, "filename": self.filename},
        )

        # waiting for eve.json to be populated
        max_tries = 30
        polling_time = 1
        for _ in range(max_tries):
            if os.path.exists(self.eve_file):
                break
            time.sleep(polling_time)

        self.s.close()

    def _json_recv(self):
        cmdret = None
        data = ""
        max_tries = 20
        for _ in range(max_tries):
            received = self.s.recv(1024).decode("iso-8859-1")
            if not received:
                break
            data += received
            if data.endswith("\n"):
                cmdret = json.loads(data)
                break
            time.sleep(1)

        return cmdret

    def _send_command(self, command, arguments=None):
        # https://suricata.readthedocs.io/en/latest/unix-socket.html
        logger.info(f"command {command}, md5 {self.md5}")
        if command == "version":
            self.s.send(bytes(json.dumps({"version": "0.2"}), "iso-8859-1"))
        else:
            cmdmsg = {"command": command}
            if arguments:
                cmdmsg["arguments"] = arguments
            cmdstr = json.dumps(cmdmsg) + "\n"
            self.s.send(
                bytes(
                    cmdstr,
                    "iso-8859-1",
                )
            )
        logger.info(f"receiving result, md5 {self.md5}")
        ready = select.select([self.s], [], [], 600)
        if ready[0]:
            cmdret = self._json_recv()
        else:
            raise Exception(f"unable to get message, md5 {self.md5}")
        logger.info(f"result received: {cmdret}, md5 {self.md5}")
        if cmdret["return"] == "NOK":
            raise Exception(f"error: {cmdret['message']}, , md5 {self.md5}")


if __name__ == "__main__":
    Suricata()

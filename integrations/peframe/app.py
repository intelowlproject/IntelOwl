# system imports
import os
import subprocess
import shutil
import hashlib
import json
import time
import logging

# web imports
from http import HTTPStatus
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_executor import Executor
from werkzeug.utils import secure_filename

# Globals
app = Flask(__name__)
executor = Executor(app)

# Config
CONFIG = {
    "SECRET_KEY": os.environ.get("FLASK_SECRET_KEY")
    or __import__("secrets").token_hex(16),
    "UPLOAD_PATH": os.environ.get("UPLOAD_PATH") or "uploads/",
    "SQLALCHEMY_DATABASE_URI": os.environ.get("DATABASE_URL") or "sqlite:///site.db",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "DEBUG": os.environ.get("FLASK_DEBUG") or False,
}
app.config.update(CONFIG)

# SQLAlchemy Models
db = SQLAlchemy(app)


class Result(db.Model):
    md5 = db.Column(db.String(128), primary_key=True, unique=True)
    timestamp = db.Column(db.Float(), default=time.time())
    report = db.Column(db.JSON(), nullable=True, default=None)
    error = db.Column(db.TEXT(), nullable=True, default=None)
    status = db.Column(db.String(20), nullable=True, default="failed")


# Utility functions
def call_peframe(f_loc, f_hash):
    """
    This function is called by the executor to run peframe
    using a subprocess asynchronously.
    """
    try:
        cmd = f"peframe -j {f_loc}"
        proc = subprocess.Popen(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        stderr = stderr.decode("ascii")
        err = None if ("SyntaxWarning" in stderr) else stderr
        if err and stdout:
            status = "reported_with_fails"
        elif stdout and not err:
            status = "success"
        else:
            status = "failed"

        # This gets stored as Future.result
        job_result = {
            "file_location": f_loc,
            "md5": f_hash,
            "stdout": json.dumps(json.loads(stdout)),
            "stderr": err,
            "status": status,
        }
        app.logger.info(f"job_{f_hash} was successful.")
        return job_result

    except Exception as e:
        job_key = f"job_{f_hash}"
        app.logger.exception(f"Caught exception:{e}")
        executor.futures._futures.get(job_key).cancel()
        app.logger.error(f"{job_key} was cancelled")
        job_result = {
            "file_location": f_loc,
            "md5": f_hash,
            "stdout": None,
            "stderr": str(e),
            "status": "failed",
        }
        return job_result


def add_result_to_db(future):
    """
    Default callable fn for Future object.
    """
    # get job result from future
    job_res = future.result()
    app.logger.debug(job_res)
    # get and update corresponding db row object
    result = Result.query.get(job_res.get("md5"))
    result.status = job_res.get("status")
    result.report = job_res.get("stdout")
    result.error = job_res.get("stderr")

    # delete file
    os.remove(job_res.get("file_location"))
    # finally commit changes to DB
    db.session.commit()


executor.add_default_done_callback(add_result_to_db)


# API routes/endpoints
@app.before_first_request
def before_first_request():
    try:
        db.drop_all()
        db.create_all()
        app.logger.debug("Dropped current DB and created new instance")
    except Exception as e:
        app.logger.exception(f"Caught Exception:{e}")
        db.create_all()
        app.logger.debug("Created new DB instance")

    _upload_path = app.config.get("UPLOAD_PATH")
    try:
        os.mkdir(_upload_path)
    except FileExistsError:
        app.logger.debug(f"Emptying upload_path:{_upload_path} folder.")
        shutil.rmtree(_upload_path, ignore_errors=True)
        os.mkdir(_upload_path)


@app.route("/run_analysis", methods=["POST"])
def run_analysis():
    try:
        # Check if file part exists
        if "file" not in request.files:
            app.logger.error("No file part in request")
            return make_response(jsonify(error="No File part"), HTTPStatus.NOT_FOUND)

        # get file and save it
        req_file = request.files["file"]
        f_name = secure_filename(req_file.filename)
        f_loc = os.path.join(app.config.get("UPLOAD_PATH"), f_name)
        req_file.save(f_loc)

        # Calc file hash
        with open(f_loc, "rb") as rf:
            f_hash = hashlib.md5(rf.read()).hexdigest()

        # Check if hash already in DB, and return directly if yes
        res = Result.query.get(f_hash)
        if res:
            app.logger.info(f"Report already exists for md5:{f_hash}")
            return make_response(
                jsonify(info="Analysis already exists", status=res.status, md5=res.md5),
                200,
            )

        app.logger.info(f"Analysis requested for md5:{f_hash}")

        # add to DB
        result = Result(md5=f_hash, status="running")
        db.session.add(result)
        db.session.commit()

        # run executor job in background
        job_key = f"job_{f_hash}"
        executor.submit_stored(
            future_key=job_key, fn=call_peframe, f_loc=f_loc, f_hash=f_hash
        )
        app.logger.info(f"Job created with key:{job_key}.")

        return make_response(jsonify(status="running", md5=f_hash), 200)

    except Exception as e:
        app.logger.exception(f"unexpected error {e}")
        return make_response(jsonify(error=str(e)), HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route("/get_report/<md5_to_get>", methods=["GET"])
def ask_report(md5_to_get):
    try:
        app.logger.info(f"Report requested for md5:{md5_to_get}")
        # check if job has been finished
        future = executor.futures._futures.get(f"job_{md5_to_get}", None)
        if future:
            if future.done:
                # pop future object since it has been finished
                executor.futures.pop(f"job_{md5_to_get}")
            else:
                return make_response(jsonify(status="running", md5=md5_to_get), 200)
        # if yes, get result from DB
        res = Result.query.get(md5_to_get)
        if not res:
            raise Exception(f"Report does not exist for md5:{md5_to_get}")

        return make_response(
            jsonify(
                status=res.status,
                md5=res.md5,
                report=json.loads(res.report),
                error=res.error,
                timestamp=res.timestamp,
            ),
            200,
        )

    except Exception as e:
        app.logger.exception(f"Caught Exception:{e}")
        return make_response(jsonify(error=str(e)), HTTPStatus.NOT_FOUND)


# Application Runner
if __name__ == "__main__":
    app.run(port=4000)
else:
    # set logger
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s"
    )
    log_level = os.getenv("LOG_LEVEL", logging.INFO)
    log_path = "/var/log/intel_owl"
    fh = logging.FileHandler(f"{log_path}/peframe.log")
    fh.setFormatter(formatter)
    fh.setLevel(log_level)
    app.logger.addHandler(fh)
    fh_err = logging.FileHandler(f"{log_path}/peframe_errors.log")
    fh_err.setFormatter(formatter)
    fh_err.setLevel(logging.ERROR)
    app.logger.addHandler(fh_err)

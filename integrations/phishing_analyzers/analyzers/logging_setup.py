import logging
import os


def setup_file_logger(log_name: str) -> logging.Logger:
    logger = logging.getLogger(log_name)

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    log_level = os.getenv("LOG_LEVEL", logging.INFO)
    log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{log_name}")

    os.makedirs(log_path, exist_ok=True)

    fh = logging.FileHandler(f"{log_path}/{log_name}.log")
    fh.setFormatter(formatter)
    fh.setLevel(log_level)

    fh_err = logging.FileHandler(f"{log_path}/{log_name}_errors.log")
    fh_err.setFormatter(formatter)
    fh_err.setLevel(logging.ERROR)

    logger.addHandler(fh)
    logger.addHandler(fh_err)
    logger.setLevel(log_level)

    return logger

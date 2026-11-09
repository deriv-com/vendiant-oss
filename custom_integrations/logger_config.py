import logging
import os
import inspect
from logging.handlers import RotatingFileHandler

def setup_logger():
    """
    Sets up a logger that dynamically names the log file based on the calling script.

    The log directory is resolved as an absolute path relative to this file's
    location (custom_integrations/logs/), which maps to the writable volume
    mounted at /app/custom_integrations/logs in the container.
    Falls back to console-only logging if the directory cannot be created
    (e.g. read-only filesystem or missing mount).

    Returns:
        logging.Logger: Configured logger instance.
    """
    frame = inspect.stack()[1]
    module = inspect.getmodule(frame[0])
    calling_script_filename = module.__file__ if module else "unknown_script"

    script_name = os.path.splitext(os.path.basename(calling_script_filename))[0]

    # Resolve logs under /app/custom_integrations/logs in the container (writable volume).
    # LOG_DIR overrides; VENDIANT_APP_ROOT anchors paths when __file__ is unavailable.
    app_root = os.environ.get("VENDIANT_APP_ROOT", "/app")
    try:
        config_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        config_dir = os.path.join(app_root, "custom_integrations")

    log_directory = os.environ.get(
        "LOG_DIR",
        os.path.join(config_dir, "logs"),
    )

    logger = logging.getLogger(script_name)
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        os.makedirs(log_directory, exist_ok=True)
        log_file_path = os.path.join(log_directory, f"{script_name}.log")
        file_handler = RotatingFileHandler(log_file_path, maxBytes=5 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Could not create log directory %s (%s). File logging disabled.", log_directory, exc)

    return logger
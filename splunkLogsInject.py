# logging_config.py
import logging
from logging.handlers import TimedRotatingFileHandler

def setup_logging():
    # Create a logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Set the root level logging

    # Create a handler for rotating logs nightly
    handler = TimedRotatingFileHandler(
        'sre_app_log.log',      # The log file path
        when='midnight',    # Rotate at midnight
        interval=1,         # Every 1 day
        backupCount=4       # Keep 7 backup files
    )
    handler.setLevel(logging.INFO)  # Set the level for the handler

    # Create a formatter and set it for the handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    # Optional: Prevent logging messages from being propagated to the root logger
    logger.propagate = False

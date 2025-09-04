import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def getLogger():
    logger.propagate = False
    handler = logging.StreamHandler()
    class SymbolFormatter(logging.Formatter):
        LEVEL_SYMBOLS = {
            logging.DEBUG: '[*]',
            logging.INFO: '[+]',
            logging.WARNING: '[!]',
            logging.ERROR: '[-]',
            logging.CRITICAL: '[X]',
        }
        def format(self, record):
            symbol = self.LEVEL_SYMBOLS.get(record.levelno, '[?]')
            return f"{symbol} {record.getMessage()}"
    handler.setFormatter(SymbolFormatter())
    logger.addHandler(handler)
    return logger

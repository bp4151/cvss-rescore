
class ManualVettingException(Exception):
    def __init__(self, msg: str):
        Exception.__init__(self, msg)

class EOFError(Exception):
    pass


class SyntaxError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class ParserError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)

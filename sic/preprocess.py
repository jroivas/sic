
class Preprocess:
    def __init__(self, fname, data=""):
        self.data = data
        if not data:
            with open(fname, "r") as fd:
                self.data = fd.read()
        self.processed = ""
        self.idx = 0

    def next(self):
        if self.idx >= len(self.data):
            return None
        c = self.data[self.idx]
        self.idx += 1
        return c

    def peek(self):
        if self.idx >= len(self.data):
            return None
        return self.data[self.idx]

    def process(self):
        while True:
            c = self.next()
            if c is None:
                break
            if c == "/":
                c2 = self.peek()
                if c2 == "*":
                    c = self.next()
                    # Comment
                    c = self.peek()
                    while c != '*' and c2 != "/":
                        c = self.next()
                        c2 = self.peek()
                        if c is None or c2 is None:
                            break
                    if c == "*" and c2 == "/":
                        c = self.next()
                elif c2 == "/":
                    c = self.next()
                    while c != "\n":
                        c = self.next()
                        if c is None:
                            break
                    if c is not None:
                        self.processed += c
                else:
                    self.processed += c
            else:
                self.processed += c

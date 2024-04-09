#!/usr/bin/env python3

import sys

from sic.token import TokenType
from sic.scan import Scan


if __name__ == "__main__":
    s = Scan(sys.argv[1])
    while True:
        t = s.scan()
        if t is None:
            break
        if t.tokentype == TokenType.INVALID:
            print("*** ERROR INVALID")
        print(t)

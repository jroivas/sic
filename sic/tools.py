def to_int(val):
    neg = False
    if val and type(val) == str and val[0] == "-":
        neg = True
        val = val[1:]
    if type(val) == str:
        if len(val) > 2 and val[0] == "0" and val[1] == "x":
            val = int(val, 16)
        elif len(val) >= 2 and val[0] == "0" and (val[1] == "o" or val[1].isdigit()):
            val = int(val, 8)
        else:
            val = int(val)
    if neg:
        if type(val) == str:
            val = "-" + val
        else:
            val = val * -1
    return val



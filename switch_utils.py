def str_to_basenum(n):
    try:
        if len(n) >=2 and n[0] == '0':
            if n[1] == 'x':
                return int(n, 16)
            elif n[1] == 'b':
                return int(n, 2)
        elif n[-1:] == 'h':
            return int(n[:-1], 16)
        return int(n, 10)
    except:
        return None

def is_printable(char):
    return char >= 0x20 and char <= 0x7E

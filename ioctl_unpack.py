import sys

def p_print(x: str):
    if x < 256 and chr(x).isprintable():
        return '0x%x (\'%s\')'%(x, chr(x))
    else:
        return '0x%x'%x

def main(argc, argv):
    if argc < 2:
        print('%s <ioctl>'%argv[0])
        return 1
    x = int(argv[1], 16)
    # https://unix.superglobalmegacorp.com/BSD4.4/newsrc/sys/ioctl.h.html
    IOCPARM_MASK = 0x1fff
    IOCPARM_LEN = (((x) >> 16) & IOCPARM_MASK)
    IOCBASECMD = ((x) & ~IOCPARM_MASK)
    IOCGROUP = (((x) >> 8) & 0xff)

    MASK = ''
    if x & 0x80000000:
        if len(MASK) > 0:
            MASK += '|'
        MASK += 'IN'
    if x & 0x40000000:
        if len(MASK) > 0:
            MASK += '|'
        MASK += 'OUT'
    if x & 0x20000000:
        if len(MASK) > 0:
            MASK += '|'
        MASK += 'VOID'
    
    print('Ioctl : 0x%08x'%x)
    print('Mask  : %s'%MASK)
    print('Group : %s'%p_print(IOCGROUP))
    print('Cmd   : %s'%p_print(x & 0xff))
    print('Length: %s'%p_print(IOCPARM_LEN))


if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))

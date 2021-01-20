import sys
import switch_utils as su

def main(argc, argv):
    """Main unpacking method"""
    if argc < 2:
        print('%s [Ioctl] ...'%argv[0])
        return
    for i in range(1, argc):
        ioctl = su.str_to_basenum(argv[i])
        length = (ioctl >> 16) & 0x1fff
        cmd = ioctl & 0xff
        group = (ioctl >> 8) & 0xff
        is_out = ioctl >> 31 # ioctl & 0x80000000
        is_in = (ioctl >> 30) & 0x1 # icotl & 0x40000000
        if su.is_printable(group):
            group = '\''+chr(group)+'\'(%d)'%group
        else:
            group = str(group)
        direction = ''
        if is_in:
            direction += 'In params'
        if is_out:
            direction += ', ' if is_in else ''
            direction += 'Out params'
        print('0x%X\n\tLength: 0x%x\n\tCmd: 0x%x\n\tGroup: %s\n\tDirection: %s'%(
            ioctl, length, cmd, group, direction))
        print('-'*32)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

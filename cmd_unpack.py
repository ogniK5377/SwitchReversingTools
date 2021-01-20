import sys

SUBMISSION_MODES = [
    "UNKNOWN_0",
    "Increasing",
    "UNKNOWWN_2",
    "NonIncreasing",
    "Inline",
    "IncreaseOnce"
]

SUBCHANNEL = [
    "3D",
    "Compute",
    "Inline",
    "2D",
    "Copy",
    "Unknown5",
    "Gpfifo"
]

def ShiftField(field, pos, size):
    new_field = field & (1 << size) - 1
    return (new_field << pos) & 0xffffffff

def DecodeToInt(n):
    if n[0:2] == '0x':
        return int(n[2:], 16)
    return int(n)

def main(argc, argv):
    if argc < 2:
        print('{} <cmd>'.format(argv[0]))
        return 1
    
    cmd = DecodeToInt(argv[1])
    
    method = cmd & 0x1fff
    subchannel = (cmd>>13) & 0x7
    arg = (cmd >> 16) & 0x1fff
    mode = (cmd >> 29) & 0x7
    
    print('Method: 0x%x'%method)
    print('Subchannel: %x(%s)'%(subchannel, SUBCHANNEL[subchannel]))
    print('Arg: %x'%arg)
    print('Submission Mode: %x(%s)'%(mode, SUBMISSION_MODES[mode]))

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))

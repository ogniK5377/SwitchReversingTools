import sys
from colorama import init, Fore, Back, Style
init()
FLIP_FLOP = False

class Helpers:
    @staticmethod
    def Str2Num(x):
        if x[:2] == '0x':
            return int(x[2:], 16)
        elif x[0] == 'b':
            print x[1:]
            return int(x[1:], 2)
        else:
            if x.isdigit():
                return int(x)
        return None

    @staticmethod
    def GetNumStrLen(x):
        if x < 10:
            return 1
        if x < 100:
            return 2
        if x < 1000:
            return 3
        if x < 10000:
            return 4

    @staticmethod
    def PadToLength(x, l):
        cur_l = len(x)
        remaining = l - cur_l
        if remaining > 0:
            return (' ' * remaining) + x
        return x

    @staticmethod
    def CountBits(n):
        n = (n & 0x5555555555555555) + ((n & 0xAAAAAAAAAAAAAAAA) >> 1)
        n = (n & 0x3333333333333333) + ((n & 0xCCCCCCCCCCCCCCCC) >> 2)
        n = (n & 0x0F0F0F0F0F0F0F0F) + ((n & 0xF0F0F0F0F0F0F0F0) >> 4)
        n = (n & 0x00FF00FF00FF00FF) + ((n & 0xFF00FF00FF00FF00) >> 8)
        n = (n & 0x0000FFFF0000FFFF) + ((n & 0xFFFF0000FFFF0000) >> 16)
        n = (n & 0x00000000FFFFFFFF) + ((n & 0xFFFFFFFF00000000) >> 32) # This last & isn't strictly necessary.
        return n

class ArgContext:
    def __init__(self):
        self.bit_length = 64
        self.decimal = False
        self.hex = False
        self.optimize_small = False
        self.numbers = []
        self.named = []
        self.n_count = 0
    
    def parse(self, argc, argv):
        i = 0
        for arg in argv:
            i+=1
            if i == 1:
                continue
            if arg[0] == '-':
                switch = arg[1:]
                if switch.startswith('l=') or switch.startswith('bit-length='):
                    self.bit_length = Helpers.Str2Num(switch[switch.index('=') + 1:])
                    continue
                if switch == 'd':
                    self.decimal = True
                if switch == 'h':
                    self.hex = True
                if switch == 'o': # Optimize bit-length for smallest type
                    self.optimize_small = True
                if switch.startswith('n='):
                    self.named[len(self.named) - 1] = switch[switch.index('=') + 1:]
            n = Helpers.Str2Num(arg)
            if n is not None:
                self.numbers.append(n)
                self.named.append(None)
                self.n_count += 1
        if self.decimal is False and self.hex is False:
            self.hex = True

        if self.optimize_small:
            self.bit_length = 0
            for n in self.numbers:
                x = Helpers.CountBits(n)
                if x > self.bit_length:
                    self.bit_length = x            
    
    def get_bit_length(self):
        return self.bit_length
    
    def get_numbers(self):
        return self.numbers
    
    def get_number(self, idx):
        if idx < self.get_number_count() and idx >= 0:
            return self.numbers[idx]
        return None
    
    def get_number_count(self):
        return self.n_count # Remove the use of len(self.numbers)

    def build_number_representation(self, idx):
        if idx < self.get_number_count() and idx >= 0:
            n = self.numbers[idx]
            x = ''
            if self.hex:
                x += '0x%x' % n
                if self.decimal:
                    x += '('
            if self.decimal:
                x += '%d' % n
                if self.hex:
                    x += ')'
            if self.named[idx] is not None:
                x += '[' + self.named[idx] + ']'
            return x
        return None


def BuildBitStr(num, bit_len=64):
    global FLIP_FLOP
    n_mask = (1 << (bit_len - 1))
    output = ''
    for i in xrange(bit_len):
        if i != 0 and i % 4 == 0:
            output += ' '
        output += (Fore.LIGHTWHITE_EX if FLIP_FLOP else Fore.LIGHTGREEN_EX) + '%d' % ((num >> ((bit_len - 1) - i)) & 1)
        n_mask >>= 1
    output += Fore.RESET
    FLIP_FLOP = not FLIP_FLOP
    return output

def PrintBitOffset(shift=0, bit_len=64):
    x = Fore.LIGHTYELLOW_EX
    x += ' ' * (shift + Helpers.GetNumStrLen(bit_len))
    for i in xrange(bit_len - 4, -4, -4):
        x += Helpers.PadToLength('%d' % i, 4) + ' '
    print x + Fore.RESET


def GetLongest(arr):
    longest = 0
    for e in arr:
        if len(e) > longest:
            longest = len(e)
    return longest
        

def main(argc, argv):
    if argc < 2:
        print '%s Number1 Number2 ...' % argv[0]
        return
    ctx = ArgContext()
    ctx.parse(argc, argv)
    
    numbers_bit = []
    numbers_rep = []

    for i in xrange(ctx.get_number_count()):
        x = BuildBitStr(ctx.get_number(i), bit_len=ctx.bit_length)
        y = ctx.build_number_representation(i)
        numbers_bit.append(x)
        numbers_rep.append(y)
    
    padding_needed = GetLongest(numbers_rep)

    PrintBitOffset(shift=padding_needed, bit_len=ctx.bit_length)
    for i in xrange(ctx.get_number_count()):
        print Helpers.PadToLength(numbers_rep[i], padding_needed) + ': ' + numbers_bit[i]
    

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)

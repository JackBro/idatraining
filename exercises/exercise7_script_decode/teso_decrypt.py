class R(object):
    eax = 0
    ecx = 0
    ebx = 0
    edx = 0
    eax = 0
    esi = 0
    edi = 0


def sub_5371048():
    R.esi = 0x5371087
    R.ecx = 0x5d05
    R.ebx = 0xc09657b0
    R.edi = R.esi
    R.edx = 0

    while R.ecx:
        R.eax = 8
        while R.eax:
            R.edx >>= 1
            if R.ebx & 1:
                R.edx |= 0x80000000
                
            R.ebx >>= 1
            if R.edx & 0x80000000:
                R.ebx ^= 0xC0000057

            R.eax -= 1
            
        R.edx >>= 24
        R.eax = Byte(R.esi)
        R.esi += 1
        R.eax ^= R.edx
        PatchByte(R.edi, R.eax)
        R.edi += 1
        R.ecx -= 1
        
        print('R.Ecx: %s' % R.ecx)
       
def main():
    sub_5371048()

main()
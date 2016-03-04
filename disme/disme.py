# from capstone import *
#
# CODE = b'\x55\x48\x8b\x05\xb8\x13\x00\x00'
#
# md = Cs(CS_ARCH_X86, CS_MODE_64)
# for i in md.disasm(CODE, 0x1000):
#     print('0x%x:\t%s\t%s'  % (i.address, i.mnemonic, i.op_str))
#

import pefile

pe = pefile.PE(r'c:\windows\system32\calc.exe')
# print(pe.DOS_HEADER.get_field_absolute_offset('e_lfanew'))

print(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

for section in pe.sections:
    if section.contains_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint):
        print(section.Name)


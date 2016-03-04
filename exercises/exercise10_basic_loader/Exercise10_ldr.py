from idaapi import *


# Verify the input file format
#   li - loader_input_t object. See IDA help file for more information
#   n  - How many times we have been called
# Returns:
#   0 - file unrecognized
#   Name of file type - if file is recognized
def accept_file(li, n):
    if (n):  # we only load one kind of file, return 0 for every call after n == 0
        return 0

    # seek to 'MZ' location, read and check magic (string of length 2)
    li.seek(0)
    e_magic = li.read(2)
    if e_magic != 'MZ':
        return 0

    # seek to e_lfanew offset (0x3c) and read offset to PE header "<I"
    li.seek(0x3C)
    header_offset = struct.unpack('<I', li.read(4))[0]

    # verify PE signature == 'PE\x00\x00'  (string of length 4)
    li.seek(header_offset)
    header = li.read(4)
    if header != 'PE\x00\x00':
        return 0

    # seek to IMAGE_NT_HEADERS.FileHeader.Machine offset, read machine word and verify == 0x14c "<H"
    li.seek(header_offset + 4 + 0)
    machine = struct.unpack('<H', li.read(2))[0]
    if machine != 0x14c:
        return 0

    # seek to IMAGE_NT_HEADERS.OptionalHeader.Magic offset, read magic word and verify = 0x10b  "<H"
    li.seek(header_offset + 24 + 0)
    magic = struct.unpack('<H', li.read(2))[0]
    if magic != 0x10b:
        return 0

    # if any of the above checks fail return 0

    # else return name of loader
    return "Basic PE32 Loader"


# Load the file
#   li - loader_input_t object
#   neflags - refer to loader.hpp for valid flags
#   format  - The file format selected by the user
# Returns:
#   1 - success
#   0 - failure
def load_file(li, neflags, format):
    # setup default data segment selector
    ds = find_free_selector()
    set_selector(ds, 0)

    # seek to e_lfanew offset and read offset to PE header  "<I"
    li.seek(0x3C)
    pe_offset = struct.unpack('<I', li.read(4))[0]

    # seek to and read IMAGE_NT_HEADER.FileHeader.NumberOfSections "<H"
    li.seek(pe_offset + 4 + 2)
    num_sections = struct.unpack('<H', li.read(2))[0]

    # seek to and read IMAGE_NT_HEADER.FileHeader.SizeOfOptionalHeader "<H"
    li.seek(pe_offset + 4 + 16)
    optionalheader_size = struct.unpack('<H', li.read(2))[0]

    # seek to and read IMAGE_NT_HEADER.OptionalHeader.AddressOfEntryPoint  "<I"
    li.seek(pe_offset + 4 + 20 + 16)
    addressofentrypoint = struct.unpack('<I', li.read(4))[0]

    # seek to and read IMAGE_NT_HEADER.OptionalHeader.ImageBase  "<I"
    li.seek(pe_offset + 4 + 20 + 28)
    imagebase = struct.unpack('<I', li.read(4))[0]

    # iterate over section headers
    # for sect in range(0, num_sections):
    # seek to beginning of next IMAGE_SECTION_HEADER and read the header "<8sIIIIIIHHI"
    offset = pe_offset + 24 + optionalheader_size
    for sect in range(0, num_sections):
        li.seek(offset + sect * 40)
        section_header = struct.unpack('<8sIIIIIIHHI', li.read(40))

        # use li.file2base to copy bytes from the file to the database
        if section_header[3] != 0:
            li.file2base(section_header[4], section_header[2] + imagebase,
                         section_header[2] + imagebase + section_header[3], 1)

        # test the characteristics (bit mask 0x20) to detemine whether the section is code or not
        if section_header[9] & 0x20 == 0x20:
            sclass = "CODE"
        else:
            sclass = "DATA"

        # use add_segm to create a new IDA segment around the newly loaded bytes
        add_segm(0, section_header[2] + imagebase, section_header[2] + section_header[1] + imagebase, section_header[0],
                 sclass)

    # use add_entry to add the initial entry point at AddressOfEntryPoint
    add_entry(addressofentrypoint + imagebase, addressofentrypoint + imagebase, '_start', True)

    # make the configured selector the default data seg selector
    # for all of the segments that we created
    set_default_dataseg(ds)

    return 1

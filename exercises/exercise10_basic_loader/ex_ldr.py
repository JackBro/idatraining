from idaapi import *

#Verify the input file format
#   li - loader_input_t object. See IDA help file for more information
#   n  - How many times we have been called
#Returns: 
#   0 - file unrecognized
#   Name of file type - if file is recognized
def accept_file(li, n):
   if (n): #we only load one kind of file, return 0 for every call after n == 0
      return 0

   #seek to 'MZ' location, read and check magic (string of length 2)

   #seek to e_lfanew offset (0x3c) and read offset to PE header "<I"

   # verify PE signature == 'PE\x00\x00'  (string of length 4)

   #seek to IMAGE_NT_HEADERS.FileHeader.Machine offset, read machine word and verify == 0x14c "<H"

   #seek to IMAGE_NT_HEADERS.OptionalHeader.Magic offset, read magic word and verify = 0x10b  "<H"

   #if any of the above checks fail return 0

   # else return name of loader
   return "Basic PE32 Loader"

#Load the file
#   li - loader_input_t object
#   neflags - refer to loader.hpp for valid flags
#   format  - The file format selected by the user
#Returns:
#   1 - success
#   0 - failure
def load_file(li, neflags, format):
   #setup default data segment selector
   ds = find_free_selector();
   set_selector(ds, 0);


   #seek to e_lfanew offset and read offset to PE header  "<I"

   #seek to and read IMAGE_NT_HEADER.FileHeader.NumberOfSections "<H"

   #seek to and read IMAGE_NT_HEADER.FileHeader.SizeOfOptionalHeader "<H"

   #seek to and read IMAGE_NT_HEADER.OptionalHeader.AddressOfEntryPoint  "<I"

   #seek to and read IMAGE_NT_HEADER.OptionalHeader.ImageBase  "<I"

   #iterate over section headers
   for sect in range(0, num_sections):
      #seek to beginning of next IMAGE_SECTION_HEADER and read the header "<8sIIIIIIHHI"

      # use li.file2base to copy bytes from the file to the database

      # use add_segm to create a new IDA segment around the newly loaded bytes
      # test the characteristics (bit mask 0x20) to detemine whether the section is code or not

   # use add_entry to add the initial entry point at AddressOfEntryPoint


   #make the configured selector the default data seg selector
   #for all of the segments that we created
   set_default_dataseg(ds);

   return 1


#include "../idaldr.h"

typedef struct __IMAGE_DOS_HEADER {      // DOS .EXE header
    unsigned short   e_magic;            // Magic number
    unsigned short   e_cblp;             // Bytes on last page of file
    unsigned short   e_cp;               // Pages in file
    unsigned short   e_crlc;             // Relocations
    unsigned short   e_cparhdr;          // Size of header in paragraphs
    unsigned short   e_minalloc;         // Minimum extra paragraphs needed
    unsigned short   e_maxalloc;         // Maximum extra paragraphs needed
    unsigned short   e_ss;               // Initial (relative) SS value
    unsigned short   e_sp;               // Initial SP value
    unsigned short   e_csum;             // Checksum
    unsigned short   e_ip;               // Initial IP value
    unsigned short   e_cs;               // Initial (relative) CS value
    unsigned short   e_lfarlc;           // File address of relocation table
    unsigned short   e_ovno;             // Overlay number
    unsigned short   e_res[4];           // Reserved unsigned shorts
    unsigned short   e_oemid;            // OEM identifier (for e_oeminfo)
    unsigned short   e_oeminfo;          // OEM information; e_oemid specific
    unsigned short   e_res2[10];         // Reserved unsigned shorts
    unsigned int     e_lfanew;           // 0x3C File address of new exe header
} _IMAGE_DOS_HEADER;

typedef struct __IMAGE_FILE_HEADER {
    unsigned short    Machine;                   //0
    unsigned short    NumberOfSections;          //2 
    unsigned int      TimeDateStamp;             //4
    unsigned int      PointerToSymbolTable;      //8
    unsigned int      NumberOfSymbols;           //12
    unsigned short    SizeOfOptionalHeader;      //16
    unsigned short    Characteristics;           //18
} _IMAGE_FILE_HEADER;                            //size 20

typedef struct __IMAGE_DATA_DIRECTORY {
    unsigned int   VirtualAddress;
    unsigned int   Size;
} _IMAGE_DATA_DIRECTORY;

typedef struct __IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    unsigned short Magic;                   //0
    unsigned char  MajorLinkerVersion;      //2
    unsigned char  MinorLinkerVersion;      //3
    unsigned int   SizeOfCode;              //4
    unsigned int   SizeOfInitializedData;   //8
    unsigned int   SizeOfUninitializedData; //12
    unsigned int   AddressOfEntryPoint;     //16
    unsigned int   BaseOfCode;              //20
    unsigned int   BaseOfData;              //24 

    //
    // NT additional fields.
    //

    unsigned int   ImageBase;                   //28
    unsigned int   SectionAlignment;            //32
    unsigned int   FileAlignment;               //36
    unsigned short MajorOperatingSystemVersion; //40
    unsigned short MinorOperatingSystemVersion; //42
    unsigned short MajorImageVersion;           //44
    unsigned short MinorImageVersion;           //46
    unsigned short MajorSubsystemVersion;       //48
    unsigned short MinorSubsystemVersion;       //50
    unsigned int   Win32VersionValue;           //52
    unsigned int   SizeOfImage;                 //56
    unsigned int   SizeOfHeaders;               //60
    unsigned int   CheckSum;                    //64
    unsigned short Subsystem;                   //68
    unsigned short DllCharacteristics;          //70
    unsigned int   SizeOfStackReserve;          //72
    unsigned int   SizeOfStackCommit;           //76
    unsigned int   SizeOfHeapReserve;           //80
    unsigned int   SizeOfHeapCommit;            //84
    unsigned int   LoaderFlags;                 //88
    unsigned int   NumberOfRvaAndSizes;         //92
    _IMAGE_DATA_DIRECTORY DataDirectory[16];    //96
} _IMAGE_OPTIONAL_HEADER32;                     //size 224

typedef struct __IMAGE_NT_HEADERS {
    unsigned int Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} _IMAGE_NT_HEADERS;

typedef struct __IMAGE_SECTION_HEADER {
    unsigned char    Name[8];              //0
    unsigned int   VirtualSize;            //8
    unsigned int   VirtualAddress;         //12
    unsigned int   SizeOfRawData;          //16
    unsigned int   PointerToRawData;       //20
    unsigned int   PointerToRelocations;   //24
    unsigned int   PointerToLinenumbers;   //28
    unsigned short NumberOfRelocations;    //32
    unsigned short NumberOfLinenumbers;    //34
    unsigned int   Characteristics;        //36
} _IMAGE_SECTION_HEADER;                   //size 40

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_pe_file(linput_t *li,
                       char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
   // read as much of the file as you need to to determine whether
   // it is something that you recognize
   if (n != 0) {  //we only recognize 1 file format, return 0 on 2nd and subsequent calls
      return 0;
   }
   if (qlseek(li, 0) != 0) {
      return 0;
   }
   
   //validate MZ magic

   //read pe offset from offset 0x3c   
 
   //validate PE signature

   //validate file header machine value is 0x14c

   //validate optional header magic is 0x10b

   //return 0 if any of the above checks fail
   
   //if you recognize the file, then say so
   qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "Basic PE32 Loader");
   return 1;
}

//--------------------------------------------------------------------------
//
//      load file into the database.
// This is only called if the user chooses our loader as the one to use
static void idaapi load_pe_file(linput_t *li, ushort neflags,
                      const char * /*fileformatname*/) {
   //NOTE, if you are using an existing Ida processor module,
   //then all you really need to do is load bytes from the file
   //into the database, create sections, and add entry points
   
   //seek to 0x3c and read pe header offset

   //seek to pe header offset and read _IMAGE_NT_HEADERS

   //compute offset to section header array 
   //pe offset + sizeof(signature) + sizeof(FileHeader) + SizeOfOptionalHeader
   
   //iterate over section headers
   for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
      //seek to beginning of section header
      
      //read section header

      //use file2base to transfer section file bytes into IDA virtual address range
      //file2base does a seek and read from the input file into the database
      //file2base is prototyped in loader.hpp

      //use add_segm to create a database section around the virtual address range of the section
      //test the section characteristics to distinguish between code and data sections

      //tell IDA tha tthe new segment is a 32 bit segment
      //retrieve a handle to the new segment
      segment_t *s = getseg(ea);    //<-- here ea is the base address of the new section
      //so that we can set 32 bit addressing mode on
      set_segm_addressing(s, 1);  //set 32 bit addressing
   }
   
   //tell IDA to create the file header comment for us.  Do this only once
   create_filename_cmt();
   //Add an entry point so that the processor module knows at least one
   //address that contains code.  This is the root of the recursive descent
   //disassembly process
   
   //use add_entry to create an entry point for AddressOfEntryPoint
   //see entry.hpp for details on add_entry
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
  IDP_INTERFACE_VERSION,
  0,                // loader flags
  accept_pe_file, // test pe format.
  load_pe_file,   // load file into the database.
  NULL,          // no saving back to PE file
  NULL,                  // no special handling for moved segments
  NULL                   // no special handling for File->New
};

//----------------------------------------------------------------------

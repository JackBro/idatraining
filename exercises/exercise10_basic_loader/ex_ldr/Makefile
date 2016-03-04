#Set this variable to point to your SDK directory
IDA_SDK=../../

PLATFORM=$(shell uname | cut -f 1 -d _)
BIN=$(shell which idaq 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(shell which idal 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(HOME)/ida/idal
endif
endif

#specify any additional libraries that you may need
EXTRALIBS=

ifneq "$(PLATFORM)" "MINGW32"
IDA=$(dir $(BIN))
endif

#Set this variable to the desired name of your compiled loader
PROC=ex_ldr

ifeq "$(PLATFORM)" "MINGW32"
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -DWIN32 -Os -fno-rtti
PLATFORM_LDFLAGS=-shared -s
LIBDIR32=$(shell find ../../ -type d | grep -E "(lib|lib/)gcc.w32")
ifeq ($(strip $(LIBDIR32)),)
LIBDIR32=../../lib/x86_win_gcc_32
IDALIB32=$(LIBDIR32)/ida.a
endif
LIBDIR64=$(shell find ../../ -type d | grep -E "(lib|lib/)gcc.w64")
ifeq ($(strip $(LIBDIR64)),)
LIBDIR64=../../lib/x86_win_gcc_64
IDALIB64=$(LIBDIR64)/ida.a
endif
LOADER_EXT32=.ldw
LOADER_EXT64=.l64
#EXTRALIBS=

else ifeq "$(PLATFORM)" "Linux"
BIN=$(shell find /opt -name idal | tail -n 1)
IDA=$(dir $(BIN))
PLATFORM_CFLAGS=-D__LINUX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)
LOADER_EXT32=.llx
LOADER_EXT64=.llx64

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"
IDA=$(shell dirname "`find /Applications -name idal | tail -n 1`")
PLATFORM_CFLAGS=-D__MAC__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"
LOADER_EXT32=.lmc
LOADER_EXT64=.lmc64

IDALIB32=-lida
IDALIB64=-lida64

endif

#Platform specific compiler flags
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32

#Platform specific ld flags
LDFLAGS=$(PLATFORM_LDFLAGS) -m32

# Destination directory for compiled plugins
OUTDIR=$(IDA_SDK)bin/loaders/

#list out the object files in your project here
OBJS=ex_ldr.o

SRCS=ex_ldr.cpp

BINARY32=$(OUTDIR)$(PROC)$(LOADER_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(LOADER_EXT64)

all: $(OUTDIR) $(BINARY32) $(BINARY64)

clean:
	-@rm *.o
	-@rm $(BINARY32)
	-@rm $(BINARY64)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

CC=g++
#CC=clang++
INC=-I$(IDA_SDK)include/

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

LD=g++
#LD=clang++

ifdef X64

%.o: %.cpp
	$(CC) -c $(CFLAGS) -D__X64__ $(INC) $< -o $@

$(BINARY64): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) -D__X64__ $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

else

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(BINARY32): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

$(BINARY64): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ -D__EA64__ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif

ex_ldr.o: ex_ldr.cpp

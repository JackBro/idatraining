#Set this variable to point to your SDK directory
IDA_SDK=../../

SDKVER=$(shell pwd | grep -o -E "idasdk[0-9]{2}" | cut -c 7- | sed 's/\(.\)\(.\)/\1\.\2/')

PLATFORM=$(shell uname | cut -f 1 -d _)
BIN=$(shell which idaq 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(shell which idal 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(HOME)/ida/idal
endif
endif

ifneq "$(PLATFORM)" "MINGW32"
IDA=$(dir $(BIN))
endif

#Set this variable to the desired name of your compiled plugin
PROC=demo_plugin

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
PLUGIN_EXT32=.plw
PLUGIN_EXT64=.p64

else ifeq "$(PLATFORM)" "Linux"
#BIN=$(shell find /opt -name idal | tail -n 1)
#IDA=$(dir $(BIN))
IDA=/opt/ida-$(SDKVER)
HAVE_IDA64=$(shell if [ -f $(IDA)/libida64.so ]; then echo -n yes; fi)
PLATFORM_CFLAGS=-D__LINUX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)
PLUGIN_EXT32=.plx
PLUGIN_EXT64=.plx64

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"
#IDA=$(shell dirname "`find /Applications -name idal | tail -n 1`")
IDAHOME=/Applications/IDA Pro $(SDKVER)
IDA=$(shell dirname "`find "$(IDAHOME)" -name idaq | tail -n 1`")
HAVE_IDA64=$(shell find "$(IDA)" -name libida64.dylib -exec echo -n yes \;)
PLATFORM_CFLAGS=-D__MAC__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"
PLUGIN_EXT32=.pmc
PLUGIN_EXT64=.pmc64
IDALIB32=-lida
IDALIB64=-lida64
endif

#Platform specific compiler flags
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32

#Platform specific ld flags
LDFLAGS=$(PLATFORM_LDFLAGS) -m32

#specify any additional libraries that you may need
EXTRALIBS=

# Destination directory for compiled plugins
OUTDIR=$(IDA_SDK)bin/plugins/

OBJDIR32=./obj32
OBJDIR64=./obj64

#list out the object files in your project here
OBJS32=	$(OBJDIR32)/demo_plugin.o
OBJS64=	$(OBJDIR64)/demo_plugin.o

SRCS=demo_plugin.cpp

BINARY32=$(OUTDIR)$(PROC)$(PLUGIN_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(PLUGIN_EXT64)

ifeq "$(HAVE_IDA64)" "yes"

all: $(OUTDIR) $(BINARY32) $(BINARY64)

else

all: $(OUTDIR) $(BINARY32)

endif

clean:
	-@rm $(OBJDIR32)/*.o
	-@rm $(OBJDIR64)/*.o
	-@rm $(BINARY32)
	-@rm $(BINARY64)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

$(OBJDIR32):
	-@mkdir -p $(OBJDIR32)

$(OBJDIR64):
	-@mkdir -p $(OBJDIR64)

CC=g++
#CC=clang
INC=-I$(IDA_SDK)include/

LD=g++
#LD=clang++

ifdef X64

$(OBJDIR64)/%.o: %.cpp
	$(CC) -c $(CFLAGS) -D__X64__ $(INC) $< -o $@

$(BINARY64): $(OBJDIR64) $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) -D__X64__ $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

else

$(OBJDIR32)/%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(OBJDIR64)/%.o: %.cpp
	$(CC) -c $(CFLAGS) -D__EA64__ $(INC) $< -o $@

$(BINARY32): $(OBJDIR32) $(OBJS32)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(OBJS32) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

$(BINARY64): $(OBJDIR64) $(OBJS64)
	$(LD) $(LDFLAGS) -o $@ $(OBJS64) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif


#change demo_plugin below to the name of your plugin, make sure to add any 
#additional files that your plugin is dependent on
$(OBJS32)/demo_plugin.o: demo_plugin.cpp

$(OBJS64)/demo_plugin.o: demo_plugin.cpp

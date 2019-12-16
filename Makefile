CC=clang
CFLAGS=-fsanitize=address -g
SRCDIR=source

SOURCE_FILES = $(SRCDIR)/armadillo.c \
			   $(SRCDIR)/bits.c \
			   $(SRCDIR)/DataProcessingImmediate.c \
			   $(SRCDIR)/BranchExcSys.c \
			   $(SRCDIR)/LoadsAndStores.c \
			   $(SRCDIR)/DataProcessingRegister.c \
			   $(SRCDIR)/DataProcessingFloatingPoint.c \
			   $(SRCDIR)/instruction.c \
			   $(SRCDIR)/strext.c \
			   $(SRCDIR)/utils.c

OBJECT_FILES = $(SRCDIR)/armadillo.o \
			   $(SRCDIR)/bits.o \
			   $(SRCDIR)/DataProcessingImmediate.o \
			   $(SRCDIR)/BranchExcSys.o \
			   $(SRCDIR)/LoadsAndStores.o \
			   $(SRCDIR)/DataProcessingRegister.o \
			   $(SRCDIR)/DataProcessingFloatingPoint.o \
			   $(SRCDIR)/instruction.o \
			   $(SRCDIR)/strext.o \
			   $(SRCDIR)/utils.o

armadillo : $(OBJECT_FILES)
	$(CC) $(CFLAGS) -dynamiclib -o libarmadillo.dylib $(OBJECT_FILES)

driver85 : $(OBJECT_FILES) driver85.c linkedlist.c
	$(MAKE) armadillo
	$(CC) $(CFLAGS) -L. -larmadillo linkedlist.c driver85.c -o driver85

asmtestcases : asmtests
	llvm-mc -triple=aarch64 -mattr=+mte,+pa,+lse,+rcpc-immo,+crc,+fmi,+fullfp16,+rdm,+dotprod,+complxnum,+fp16fml,+aes \
		--show-encoding --print-imm-hex -assemble < asmtests | perl asmtestgen > tests.txt

$(SRCDIR)/%.o : $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean :
	rm libarmadillo.dylib $(OBJECT_FILES)

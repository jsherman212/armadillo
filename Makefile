CC=clang
CFLAGS=-fsanitize=address -g
SRCDIR=source

SOURCE_FILES = $(SRCDIR)/armadillo.c \
			   $(SRCDIR)/bits.c \
			   $(SRCDIR)/DataProcessingImmediate.c \
			   $(SRCDIR)/BranchExcSys.c \
			   $(SRCDIR)/instruction.c \
			   $(SRCDIR)/strext.c \
			   $(SRCDIR)/utils.c

OBJECT_FILES = $(SRCDIR)/armadillo.o \
			   $(SRCDIR)/bits.o \
			   $(SRCDIR)/DataProcessingImmediate.o \
			   $(SRCDIR)/BranchExcSys.o \
			   $(SRCDIR)/instruction.o \
			   $(SRCDIR)/strext.o \
			   $(SRCDIR)/utils.o

armadillo : $(OBJECT_FILES)
	$(CC) $(CFLAGS) -dynamiclib -o libarmadillo.dylib $(OBJECT_FILES)

driver85 : $(OBJECT_FILES) driver85.c linkedlist.c
	$(MAKE) armadillo
	$(CC) $(CFLAGS) -L. -larmadillo linkedlist.c driver85.c -o driver85

asmtests : asmtests.c
	$(CC) -arch arm64e -isysroot /Users/justin/theos/sdks/iPhoneOS11.2.sdk asmtests.c -o asmtests

$(SRCDIR)/%.o : $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean :
	rm libarmadillo.dylib $(OBJECT_FILES)

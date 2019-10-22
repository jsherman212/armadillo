CC=clang
CFLAGS=-fsanitize=address -g
SRCDIR=source

SOURCE_FILES = $(SRCDIR)/armadillo.c \
			   $(SRCDIR)/array.c \
			   $(SRCDIR)/bits.c \
			   $(SRCDIR)/BranchExcSys.c \
			   $(SRCDIR)/DataProcessingFloatingPoint.c \
			   $(SRCDIR)/DataProcessingImmediate.c \
			   $(SRCDIR)/DataProcessingRegister.c \
			   $(SRCDIR)/instruction.c \
			   $(SRCDIR)/LoadsAndStores.c \
			   $(SRCDIR)/strext.c \
			   $(SRCDIR)/utils.c

OBJECT_FILES = $(SRCDIR)/armadillo.o \
			   $(SRCDIR)/array.o \
			   $(SRCDIR)/bits.o \
			   $(SRCDIR)/BranchExcSys.o \
			   $(SRCDIR)/DataProcessingFloatingPoint.o \
			   $(SRCDIR)/DataProcessingImmediate.o \
			   $(SRCDIR)/DataProcessingRegister.o \
			   $(SRCDIR)/instruction.o \
			   $(SRCDIR)/LoadsAndStores.o \
			   $(SRCDIR)/strext.o \
			   $(SRCDIR)/utils.o

armadillo : $(OBJECT_FILES)
	$(CC) $(CFLAGS) -dynamiclib -o libarmadillo.dylib $(SOURCE_FILES)

driver : $(OBJECT_FILES) driver.c linkedlist.c
	$(MAKE) armadillo
	$(CC) $(CFLAGS) -L. -larmadillo linkedlist.c driver.c -o driver

$(SRCDIR)/%.o : $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean :
	rm libarmadillo.dylib $(OBJECT_FILES)

CC=clang
SRCDIR=source

OBJECT_FILES = $(SRCDIR)/armadillo.o \
			   $(SRCDIR)/bits.o \
			   $(SRCDIR)/BranchExcSys.o \
			   $(SRCDIR)/DataProcessingFloatingPoint.o \
			   $(SRCDIR)/DataProcessingImmediate.o \
			   $(SRCDIR)/DataProcessingRegister.o \
			   $(SRCDIR)/instruction.o \
			   $(SRCDIR)/LoadsAndStores.o \
			   $(SRCDIR)/utils.o

armadillo : $(OBJECT_FILES)
	$(CC) $(OBJECT_FILES)

$(SRCDIR)/%.o : $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) -c $< -o $@

.PHONY: clean

clean :
	rm $(OBJECT_FILES)

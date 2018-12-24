CC=clang
CFLAGS=-g -fsanitize=address
LDFLAGS=-fsanitize=address
SRCDIR=source

OBJECT_FILES = $(SRCDIR)/armadillo.o \
			   $(SRCDIR)/bits.o \
			   $(SRCDIR)/BranchExcSys.c \
			   $(SRCDIR)/DataProcessingFloatingPoint.o \
			   $(SRCDIR)/DataProcessingImmediate.o \
			   $(SRCDIR)/DataProcessingRegister.o \
			   $(SRCDIR)/driver.o \
			   $(SRCDIR)/instruction.o \
			   $(SRCDIR)/linkedlist.o \
			   $(SRCDIR)/LoadsAndStores.o \
			   $(SRCDIR)/utils.o

armadillo : $(OBJECT_FILES)
	$(CC) $(OBJECT_FILES) $(LDFLAGS) -o armadillo

$(SRCDIR)/%.o : $(SRCDIR)/%.c $(SRCDIR)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

tests : tests/tests.o
	ld -syslibroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.1.sdk/ tests/tests.o -o tests/tests -iphoneos_version_min 12.1.0 -lSystem

tests/tests.o : tests/tests.c
	$(CC) -arch arm64 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.1.sdk/ -c tests/tests.c -o tests/tests.o

asmgen : asmgen.c
	gcc asmgen.c -o asmgen

clean :
	rm armadillo $(OBJECT_FILES)

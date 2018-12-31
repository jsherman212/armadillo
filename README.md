# armadillo

Armadillo is an ARM64/ARMv8 disassembler written in C. I wrote it for the debugger I'm working on - https://github.com/jsherman212/iosdbg, but I made sure it could be easily included in other projects.

This project disassembles up to and including ARMv8.4, and is guaranteed to compile and work on macOS and jailbroken iOS.

## Getting started

#### macOS
It's very straightforward to get this set up on macOS. Run these commands to get the library built:

```
git clone https://github.com/jsherman212/armadillo.git
cd armadillo
make
```

You should see `libarmadillo.dylib` in your current working directory. You will need this and `source/armadillo.h` for your project. Copy those two files to your project folder.

#### Jailbroken iOS

##### Theos
Skip this step if it's already installed on your device.

Theos is a cross-platform suite of tools capable of building iOS software without Xcode. Refer to this link for instructions on installing Theos on your jailbroken iOS device: https://github.com/theos/theos/wiki/Installation-iOS

I have built and used this project with the iOS 11.2 SDK on an iPhone running iOS 10.3.2, but it should work for other versions.

SSH into your device as `root` and run these commands to get the library built:

```
cd /var/mobile
git clone https://github.com/jsherman212/armadillo.git
cd armadillo
make CFLAGS='-isysroot /path/to/your/SDK/'
```

You should see `libarmadillo.dylib` in your current working directory. You will need this and `source/armadillo.h` for your project. Copy those two files to your project folder.

Because this is iOS, we need to sign `libarmadillo.dylib`. You can use ldid or jtool to fakesign it, or you could use Apple's codesign utility. It is easier to fakesign it:

`ldid -S libarmadillo.dylib`

If all went well the library will be ready to use.

## API
Armadillo has a very simple API. Assuming you have copied `libarmadillo.dylib` and `source/armadillo.h` to your project folder, you need to add `#include "armadillo.h"`.

There are two functions for you to use:
```
char *ArmadilloDisassemble(unsigned int hex, unsigned long PC);
char *ArmadilloDisassembleB(unsigned int hex, unsigned long PC);
```

*You must free the pointer returned by those functions.*

`ArmadilloDisassemble` takes in **little endian** `hex` representing the instruction and `PC`, or where the instruction resides in memory. If the location of the instruction does not matter, `PC` is ignored, and can be any value. `PC` is generally only used with branches and a few other instructions. This function returns a C string containing the disassembly of `hex`, `undefined`, or `unknown`. *This string must be freed.*

`ArmadilloDisassembleB` is the exact same as `ArmadilloDisassemble`, but `hex` is in **big endian** instead of little endian.

Compile your project and link with `libarmadillo` and you should be good to go.

See `example.c` for example usage.

## Contributing
While I may not be open to contributions, I am open to suggestions.
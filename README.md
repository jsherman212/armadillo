# armadillo

Armadillo is an ARM64/ARMv8 disassembler. I wrote it for the debugger I'm working on - https://github.com/jsherman212/iosdbg, but I made sure it could be easily included in other projects.

This project disassembles up to and including ARMv8.5.

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

We need to sign `libarmadillo.dylib`. You can use ldid or jtool to fakesign it, or you could use Apple's codesign utility. It is easier to fakesign it:

`ldid -S libarmadillo.dylib`

If all went well the library will be ready to use.

## API
The main structure is `struct ad_insn`. It will contain info about a disassembled instruction after a successful call to ArmadilloDisassemble:

```
struct ad_insn {
    /* instruction disassembly */
    char *decoded;

    /* which top level decode group this instruction belongs to (AD_G_*) */
    int group;
    /* unique instruction ID (AD_INSTR_*) */
    int instr_id;

    /* array of decode fields, going from left to right (as per the manual) */
    int *fields;
    int num_fields;

    /* array of ad_operand structs, going from left to right (according to the disassembly) */
    struct ad_operand *operands;
    int num_operands;

    /* code condition, if any (AD_CC_*) */
    int cc;
};
```

There are two functions for you to use:

```
int ArmadilloDisassemble(unsigned int opcode, unsigned long PC, struct ad_insn **out);
int ArmadilloDone(struct ad_insn **insn);
```

`ArmadilloDisassemble` takes in a **little endian** `opcode`, and an optional `PC` value. `out`, the address of a pointer to an `ad_insn` struct, will be filled with details about the instruction upon return. This function returns non-zero on error. You must always pass the returned `ad_insn` struct to `ArmadilloDone`, even on error, to free memory which could have been allocated before said error.

`ArmadilloDone` takes the address of a pointer to an `ad_insn` structure and deallocates memory. It is always safe to reuse an `ad_insn` structure after ArmadilloDone has returned, even upon error. Returns non-zero on error.

`example.c` showcases some of the information you get back from the `ad_insn` structure:

```
$ clang example.c -L. -larmadillo -o example
$ ./example
Disassembled: sub x5, x4, #0x20
	This instruction is AD_INSTR_SUB and is part of group AD_G_DataProcessingImmediate
	This instruction has 7 decode fields (from left to right):
		0x1, 0x1, 0, 0, 0x20, 0x4, 0x5
	This instruction has 3 operands (from left to right):
		This operand is of type AD_OP_REG
			Register: x5
		This operand is of type AD_OP_REG
			Register: x4
		This operand is of type AD_OP_IMM
			Immediate type: AD_IMM_ULONG
			Value: 0x20

Disassembled: b 0x100007f70
	This instruction is AD_INSTR_B and is part of group AD_G_BranchExcSys
	This instruction has 2 decode fields (from left to right):
		0, 0x10
	This instruction has 1 operands (from left to right):
		This operand is of type AD_OP_IMM
			Immediate type: AD_IMM_LONG
			Value: 0x100007f70

Disassembled: mrs x0, TTBR0_EL1
	This instruction is AD_INSTR_MRS and is part of group AD_G_BranchExcSys
	This instruction has 7 decode fields (from left to right):
		0x1, 0x1, 0, 0x2, 0, 0, 0
	This instruction has 2 operands (from left to right):
		This operand is of type AD_OP_REG
			Register: x0
		This operand is of type AD_OP_REG
			System register: TTBR0_EL1

Disassembled: ushll2 v6.4s, v2.8h, #0x1
	This instruction is AD_INSTR_USHLL2 and is part of group AD_G_DataProcessingFloatingPoint
	This instruction has 7 decode fields (from left to right):
		0x1, 0x1, 0x2, 0x1, 0x14, 0x2, 0x6
	This instruction has 3 operands (from left to right):
		This operand is of type AD_OP_REG
			Register: v6
		This operand is of type AD_OP_REG
			Register: v2
		This operand is of type AD_OP_IMM
			Immediate type: AD_IMM_UINT
			Value: 0x1

Disassembled: bti jc
	This instruction is AD_INSTR_BTI and is part of group AD_G_BranchExcSys
	This instruction has 2 decode fields (from left to right):
		0x4, 0x6
	This instruction has 0 operands (from left to right):

Disassembled: fmov d9, #-0.296875
	This instruction is AD_INSTR_FMOV and is part of group AD_G_DataProcessingFloatingPoint
	This instruction has 6 decode fields (from left to right):
		0, 0, 0x1, 0xd3, 0, 0x9
	This instruction has 2 operands (from left to right):
		This operand is of type AD_OP_REG
			Register: d9
		This operand is of type AD_OP_IMM
			Immediate type: AD_IMM_FLOAT
			Value: -0.296875
```

## Contributing
While I may not be open to contributions, I am open to suggestions.

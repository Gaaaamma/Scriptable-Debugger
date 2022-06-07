# Scriptable-Debugger
1102_UNIX_Programming Class HW4<br>
Advanced Programming in the UNIX Environment<br>
Due: Jun 6, 2022 Extended to Jun 13, 2022 (hard-deadline)<br>
*** The difficulty of this homework has been simplified to handle only non-PIE programs.

## Result Overview
### User operation
Use debugger to set regs to pass the compare of numbers
<img width="776" alt="截圖 2022-06-07 下午4 53 24" src="https://user-images.githubusercontent.com/84212529/172340322-f0925754-6247-4637-92c2-40e6d6932e54.png">


### Scriptable operation
Same operation can be done with self defined scripts
<img width="779" alt="截圖 2022-06-07 下午4 56 55" src="https://user-images.githubusercontent.com/84212529/172340011-d77f04be-2282-4726-a6a3-3b28b5742904.png">

## Simplified Scriptable Instruction Level Debugger
In this homework, you have to implement a simple instruction-level debugger that allows a user to debug a program interactively at the assembly instruction level. You can implement the debugger by using the ptrace interface. The commands you have to implement are summarized as follows:
```
- break {instruction-address}: add a break point
- cont: continue execution
- delete {break-point-id}: remove a break point
- disasm addr: disassemble instructions in a file or a memory region
- dump addr: dump memory content
- exit: terminate the debugger
- get reg: get a single value from a register
- getregs: show registers
- help: show this message
- list: list break points
- load {path/to/a/program}: load a program
- run: run the program
- vmmap: show memory layout
- set reg val: get a single value to a register
- si: step into instruction
- start: start the program and stop at the first instruction
```

In a debugging process, you have to load a program first, configure the debugger, and start debugging by running the program. A debugger command may be only used in certain "states." The states include any, not loaded, loaded, and running. State any means that a command can be used at any time. State not loaded means that a command can only be used when a program is not loaded. State loaded means that a command can only be used when a program is loaded. State running means that a command can only be used when the program is running. The following is the state flow chart.
<br><img width="527" alt="截圖 2022-06-07 下午4 59 39" src="https://user-images.githubusercontent.com/84212529/172340985-d858527c-b46d-4da3-bfa9-8f5889fce489.png">



The details of each command are explained below. We use brackets right after a command to enclose the list of the state(s) that the command should support.

- **break or b [running]:** <br>Setup a break point. If a program is loaded but is not running, you can simply display an error message. When a break point is hit, you have to output a message and indicate the corresponding address and instruction. The address of the break point should be within the range specified by the text segment in the ELF file and will not be the same as the entry point.
- **cont or c [running]:** <br>continue the execution when a running program is stopped (suspended).
- **delete [running]:** <br>remove a break point. Please remember to handle illegal situations, like deleting non-existing break points.
- **disasm or d [running]:** <br>Disassemble instructions in a file or a memory region. The address of each instruction should be within the range specified by the text segment in the ELF file. You only have to dump 10 instructions for each command. If disasm command is executed without an address, you can simply output ** no addr is given. Please note that the output should not have the machine code cc. See the demonstration section for the sample output format.
- **dump or x [running]:** <br>Dump memory content. You only have to dump 80 bytes from a given address. The output contains the addresses, the hex values, and printable ASCII characters. If dump command is executed without an address, you can simply output ** no addr is given. Please note that the output should include the machine code cc if there is a break point.
- **exit or q [any]:** <br>Quit from the debugger. The program being debugged should be killed as well.
- **get or g [running]:** <br>Get the value of a register. Register names are all in lowercase.
- **getregs [running]:** <br>Get the value of all registers.
- **help or h [any]:** <br>Show the help message.
- **list or l [any]:** <br>List break points, which contains index numbers (for deletion) and addresses.
- **load [not loaded]:** <br>Load a program into the debugger. When a program is loaded, you have to print out the address of entry point.
- **run or r [loaded and running]:** <br>Run the program. If the program is already running, show a warning message and continue the execution. If the program is loaded, start the program and continue the execution.
- **vmmap or m [running]:** <br>Show memory layout for a running program. If a program is not running, you can simply display an error message.<br>The memory layout is:
```[address] [perms] [offset] [pathname]```<br>Check the demonstration section for the sample output format.
- **set or s [running]:** <br>Set the value of a register
- **si [running]:** <br>Run a single instruction, and step into function calls.
- **start [loaded]:** <br>Start the program and stop at the first instruction.

Your program may output some debug messages. In that case, please add "\*\*" prefixes before your message. We will remove lines beginning with "\*\*" when comparing outputs.

Your program should read user commands from either user inputs (by default) or a predefined script (if -s option is given). Please check the demonstration section for the sample input and the corresponding output for more details about the implementation. The usage of this homework is:
```
usage: ./hw4 [-s script] [program]
```
## Demonstration
We use the hello world and the guess.nopie program introduced in the class to demonstrate the usage of the simple debugger. User typed commands are marked in blue.

### Load a program, show maps, and run the program (hello64)
```
$ ./hw4
sdb> load sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 16328
sdb> vmmap
0000000000400000-0000000000401000 r-x 0        /home/chuang/unix_prog/hw4_sdb/sample/hello64
0000000000600000-0000000000601000 rwx 0        /home/chuang/unix_prog/hw4_sdb/sample/hello64
00007ffe29604000-00007ffe29625000 rwx 0        [stack]
00007ffe29784000-00007ffe29787000 r-- 0        [vvar]
00007ffe29787000-00007ffe29789000 r-x 0        [vdso]
7fffffffffffffff-7fffffffffffffff r-x 0        [vsyscall]
sdb> get rip
rip = 4194480 (0x4000b0)
sdb> run
** program sample/hello64 is already running
hello, world!
** child process 16328 terminiated normally (code 0)
sdb>
```

### Start a progrm, and show registers
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 30433
sdb> getregs
RAX 0                 RBX 0                 RCX 0                 RDX 0               
R8  0                 R9  0                 R10 0                 R11 0               
R12 0                 R13 0                 R14 0                 R15 0               
RDI 0                 RSI 0                 RBP 0                 RSP 7ffc51e88280    
RIP 4000b0            FLAGS 0000000000000200
sdb>
```

### Start a program, set a break point, step into instruction, continue the execution, and run the program again without start (hello64).
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 74303
sdb> b 0x4000b5
sdb> b 0x4000ba
sdb> cont
** breakpoint @      4000b5: bb 01 00 00 00                     mov       ebx, 1
sdb> si
** breakpoint @      4000ba: b9 d4 00 60 00                     mov       ecx, 0x6000d4
sdb> cont
hello, world!
** child process 74303 terminiated normally (code 0)
sdb> run
** pid 74325
** breakpoint @      4000b5: bb 01 00 00 00                     mov       ebx, 1
sdb> 
```

### Start a program, set a break point, continue the execution, check assembly output, and dump memory (hello64)
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 20354
sdb> disasm
** no addr is given.
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                 mov    eax, 4
      4000b5: bb 01 00 00 00                 mov    ebx, 1
      4000ba: b9 d4 00 60 00                 mov    ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                 mov    edx, 0xe
      4000c4: cd 80                          int    0x80
      4000c6: b8 01 00 00 00                 mov    eax, 1
      4000cb: bb 00 00 00 00                 mov    ebx, 0
      4000d0: cd 80                          int    0x80
      4000d2: c3                             ret
** the address is out of the range of the text segment
sdb> b 0x4000c6
sdb> disasm 0x4000c6
      4000c6: b8 01 00 00 00                 mov    eax, 1
      4000cb: bb 00 00 00 00                 mov    ebx, 0
      4000d0: cd 80                          int    0x80
      4000d2: c3                             ret
** the address is out of the range of the text segment
sdb>  cont
hello, world!
** breakpoint @      4000c6: b8 01 00 00 00                     mov       eax, 1
sdb> disasm 0x4000c6
      4000c6: b8 01 00 00 00                 mov    eax, 1
      4000cb: bb 00 00 00 00                 mov    ebx, 0
      4000d0: cd 80                          int    0x80
      4000d2: c3                             ret
** the address is out of the range of the text segment
sdb> dump 0x4000c6
      4000c6: cc 01 00 00 00 bb 00 00 00 00 cd 80 c3 00 68 65  |..............he|
      4000d6: 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a 00 00 00 00  |llo, world!.....|
      4000e6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
      4000f6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 00  |................|
      400106: 01 00 b0 00 40 00 00 00 00 00 00 00 00 00 00 00  |....@...........|
sdb>
```

### Load a program, disassemble, set break points, run the program, and change the control flow (hello64).
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 16690
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                     mov       eax, 4
      4000b5: bb 01 00 00 00                     mov       ebx, 1
      4000ba: b9 d4 00 60 00                     mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                     mov       edx, 0xe
      4000c4: cd 80                              int       0x80
      4000c6: b8 01 00 00 00                     mov       eax, 1
      4000cb: bb 00 00 00 00                     mov       ebx, 0
      4000d0: cd 80                              int       0x80
      4000d2: c3                                 ret
** the address is out of the range of the text segment
sdb> b 0x4000c6
sdb> l
  0:  4000c6
sdb> cont
hello, world!
** breakpoint @       4000c6: b8 01 00 00 00                 mov    eax, 1
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** breakpoint @       4000c6: b8 01 00 00 00                 mov    eax, 1
sdb> delete 0
** breakpoint 0 deleted.
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** child process 16690 terminiated normally (code 0)
sdb>
```

### Load a program, set break points, run the program, and change the control flow (guess).
```
$ ./hw4 sample/guess.nopie
** program 'sample/guess' loaded. entry point 0x4006f0
sdb> start
** pid 17133
sdb> b 0x400879
sdb> cont
Show me the key: 1234
** breakpoint @ 5559c2a739cc: 48 39 d0                       cmp    rax, rdx
sdb> get rax
rax = 1234 (0x4d2)
sdb> get rdx
rdx = 17624781 (0x10ceecd)
sdb> set rax 5678
sdb> set rdx 5678
sdb> cont
Bingo!
** child process 17133 terminiated normally (code 0)
sdb>
```

## Sample Scripts (30%) && Hidden Scripts(70%)
### Sample scripts passed to your homework (with -s option) can be found here!

Please note that the debugger is exited directly after the script is executed.
### hello1.txt (6%)
```
help
load sample/hello64
start
disasm 0x4000b0
```
### hello2.txt (6%)
```
load sample/hello64
vmmap
start
vmmap
getregs
get rip
run
```
### hello3.txt (6%)
```
load sample/hello64
start
b 0x4000c6
cont
get rip
set rip 0x4000b0
cont
get rip
set rip 0x4000b0
cont
cont
```
### hello4.txt (6%)
```
load sample/hello64
start
b 0x4000c6
l
cont
set rip 0x4000b0
cont
delete 0
set rip 0x4000b0
cont
```
### guess.txt (6%)
```
start
b 0x400879
cont
get rax
get rdx
set rdx 5678
set rax 5678
cont
```
Two examples of running scripts are given as follows.
### 1. Print 'hello, world!' for three times.
```
$ ./hw4 -s scripts/hello3.txt 2>&1 | grep -v '^\*\*'
hello, world!
rip = 4194502 (0x4000c6)
hello, world!
rip = 4194502 (0x4000c6)
hello, world!
$
```

### 2. Auto debugger for guess
```
$ ./hw4 -s scripts/guess.txt sample/guess.nopie 2>&1 | grep -v '^\*\*'
1234
rax = 1234 (0x4d2)
rdx = 580655839 (0x229c1adf)
Show me the key: Bingo!
$
```

## Hints
Here we provide some hints for implementing this homework.

For disassembling, you have to link against the capstone library. You may refer to the official capstone C tutorial or the ptrace slide for the usage.

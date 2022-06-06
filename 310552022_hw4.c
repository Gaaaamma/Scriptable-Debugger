#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/user.h>
#include <errno.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <capstone/capstone.h>
//******************************//
//        Global Define         //
//******************************//
#define INPUTSIZE 256
#define MAPSSIZE 1000
#define DBYTE 16
#define DUMPTIMES 10
#define MAX_BREAKPOINT_NUM 100
#define MAX_DISASM_INS 10
#define MAX_CHAR_PERINS 10

char helpMsg[] = "- break {instruction-address}: add a break point\n- cont: continue execution\n- delete {break-point-id}: remove a break point\n- disasm addr: disassemble instructions in a file or a memory region\n- dump addr: dump memory content\n- exit: terminate the debugger\n- get reg: get a single value from a register\n- getregs: show registers\n- help: show this message\n- list: list break points\n- load {path/to/a/program}: load a program\n- run: run the program\n- vmmap: show memory layout\n- set reg val: get a single value to a register\n- si: step into instruction\n- start: start the program and stop at the first instruction\n";
const char delima[3] = " \n";
typedef enum{
    NOTLOADED,
    LOADED,
    RUNNING,
    START
}stage_t;


typedef struct{
    // record the number of breakpoints
    int num; 
    // record breakpoint address
    unsigned long long breakpointAddress[MAX_BREAKPOINT_NUM];
    // record breakpoint original byte command
    long originalCommand[MAX_BREAKPOINT_NUM];
}breakpoint_t;
breakpoint_t breakpoints;

//******************************//
//          functions           //
//******************************//
void checkBreakpoint();
void addBreakpoint(pid_t child, unsigned long long address, unsigned long int lowBound, unsigned long int highBound);
void rmBreakpoint(pid_t child, int index);
void disasm(uint8_t *code, size_t codeSize, uint64_t startAddress, unsigned long int lowBound, unsigned long int highBound);
int findTextIndex(char *fname, size_t size);
void setRegs(pid_t child, char* target, char *value, struct user_regs_struct *regs);
char* offsetHandling(char *offset);
char* addLackZero(char *padding, char *target);
void printRegs(char* target, struct user_regs_struct regs);
void errquit(const char *msg);
void handleScriptPath(int argc, char* argv[], char* scriptPath);

//******************************//
//             main             //
//******************************//
int main(int argc, char* argv[]){
    stage_t stage = NOTLOADED;
    pid_t child;
    int childStatus;

    int elfFd = 0;
    Elf64_Ehdr elfHeader;
    Elf64_Shdr secHeader;
    unsigned long int lowBound = 0;
    unsigned long int highBound = 0;

    unsigned char *codeBuf = (unsigned char *)malloc(MAX_CHAR_PERINS * MAX_DISASM_INS * sizeof(char));
    memset(codeBuf, 0, MAX_CHAR_PERINS * MAX_DISASM_INS * sizeof(char));

    // Initialization breakpoints
    breakpoints.num = 0;
    memset(breakpoints.breakpointAddress,0,MAX_BREAKPOINT_NUM);
    memset(breakpoints.originalCommand,0,MAX_BREAKPOINT_NUM);

    int hasScript, hasExecutable=0;
    char scriptPath[INPUTSIZE] = {};
    char executable[INPUTSIZE] = {};

    // scriptPath && executable file path parsing
    if(argc > 1){
        handleScriptPath(argc,argv,scriptPath);
        if(strcmp(scriptPath,"") ==0){
            // No script -> argument is executable program path
            hasExecutable = 1;
            strcat(executable,argv[argc-1]);

        }else{
            // Has script -> check if executable exist
            hasScript = 1;
            if(strcmp(scriptPath,argv[argc-1]) !=0){
                // executable exist
                hasExecutable = 1;
                strcat(executable, argv[argc-1]);
            }
        }
    }
    fprintf(stderr, "** scriptPath: %s\n", scriptPath);
    fprintf(stderr, "** executable file: %s\n", executable);

    // if hasExecutable -> load exe first 
    if(hasExecutable){
        // preworking with executable path
        if ((child = fork()) < 0){
            errquit("fork");
        }
            
        if (child == 0){ // Child
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
                errquit("ptrace");
            }
            execlp(executable, executable, NULL);
            errquit("execlp");

        }else{ // Parent
            if (waitpid(child, &childStatus, 0) < 0){
                errquit("waitpid");
            }
            assert(WIFSTOPPED(childStatus));
            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

            // 0. Get child entry point and data
            elfFd = open(executable, S_IRUSR);
            read(elfFd, &elfHeader, sizeof(Elf64_Ehdr));
            
            // 1. Show entry point infomation
            fprintf(stderr,"** program \'%s\' loaded. entry point 0x%lx\n", executable, elfHeader.e_entry);

            // 2. Show .text lowBound && highBound
            struct stat st;
            if (stat(executable, &st) != 0) errquit("stat");

            // lseek to section header offset
            int textIndex = findTextIndex(executable, st.st_size);
            
            lseek(elfFd, elfHeader.e_shoff, SEEK_SET);
            for (int i = 0; i < elfHeader.e_shnum; i++){
                read(elfFd, &secHeader, sizeof(Elf64_Shdr));
                // check if section is .text or not
                if (secHeader.sh_name == textIndex){
                    // record .text lowBound && .text highBound
                    lowBound = secHeader.sh_addr;
                    highBound = lowBound + secHeader.sh_size - 1;
                    fprintf(stderr, "** .text lowBound:  0x%lx\n", lowBound);
                    fprintf(stderr, "** .text highBound: 0x%lx\n", highBound);
                }
            }
        }
        stage = LOADED;
    }

    // NOTLOADED stage 
    while(stage == NOTLOADED){
        char input[INPUTSIZE] = {};
        fprintf(stderr,"sdb> ");
        fgets(input,INPUTSIZE,stdin);
        char *command = strtok(input, delima);

        // Parsing
        if(strncmp(command,"help",INPUTSIZE) == 0 || strncmp(command,"h",INPUTSIZE) ==0){
            fprintf(stderr,"%s",helpMsg);

        }else if(strncmp(command,"exit",INPUTSIZE) == 0 || strncmp(command,"q",INPUTSIZE) ==0){
            exit(0);

        }else if(strncmp(command,"list",INPUTSIZE) == 0 || strncmp(command,"l",INPUTSIZE) ==0){
            checkBreakpoint();

        }else if(strncmp(command,"load",INPUTSIZE) == 0){
            // keep spliting
            command = strtok(NULL, delima);
            strcat(executable, command);

            if ((child = fork()) < 0){
                errquit("fork");
            }

            // load process
            if (child == 0){ // Child
                if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
                    errquit("ptrace");
                }
                execlp(executable, executable, NULL);
                errquit("execlp");

            }else{ // Parent
                if (waitpid(child, &childStatus, 0) < 0){
                    errquit("waitpid");
                }
                assert(WIFSTOPPED(childStatus));
                ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

                // 0. Get child entry point and data
                elfFd = open(executable, S_IRUSR);
                read(elfFd, &elfHeader, sizeof(Elf64_Ehdr));

                // 1. Show entry point infomation
                fprintf(stderr,"** program \'%s\' loaded. entry point 0x%lx\n", executable, elfHeader.e_entry);

                // 2. Show .text lowBound && highBound
                struct stat st;
                if (stat(executable, &st) != 0) errquit("stat");

                // lseek to section header offset
                int textIndex = findTextIndex(executable, st.st_size);
                lseek(elfFd, elfHeader.e_shoff, SEEK_SET);

                for (int i = 0; i < elfHeader.e_shnum; i++){
                    read(elfFd, &secHeader, sizeof(Elf64_Shdr));
                    // check if section is .text or not
                    if (secHeader.sh_name == textIndex){
                        // record .text lowBound && .text highBound
                        lowBound = secHeader.sh_addr;
                        highBound = lowBound + secHeader.sh_size - 1;
                        fprintf(stderr, "** .text lowBound:  0x%lx\n", lowBound);
                        fprintf(stderr, "** .text highBound: 0x%lx\n", highBound);
                    }
                }
            }
            stage = LOADED;

        }else{
            fprintf(stderr,"** Invalid command at NOTLOADED stage: %s\n",input);
        }
    }
    
    // debugger keep working
    while(1){
        // LOADED stage
        while (stage == LOADED){
            char input[INPUTSIZE] = {};
            fprintf(stderr,"sdb> ");
            fgets(input,INPUTSIZE,stdin);
            char *command = strtok(input, delima);

            // Parsing
            if(strncmp(command,"help",INPUTSIZE) == 0 || strncmp(command,"h",INPUTSIZE) ==0){
                fprintf(stderr,"%s",helpMsg);

            }else if(strncmp(command,"exit",INPUTSIZE) == 0 || strncmp(command,"q",INPUTSIZE) ==0){
                exit(0);

            }else if(strncmp(command,"list",INPUTSIZE) == 0 || strncmp(command,"l",INPUTSIZE) ==0){
                checkBreakpoint();

            }else if(strncmp(command,"run",INPUTSIZE) == 0 || strncmp(command,"r",INPUTSIZE) ==0){
                ptrace(PTRACE_CONT, child, 0, 0);
                stage = RUNNING;
            }else if(strncmp(command,"start",INPUTSIZE) == 0){
                fprintf(stderr,"** pid %d\n", child);
                stage = START;
            }else{
                fprintf(stderr,"** Invalid command at LOADED stage: %s\n",input);
            }
        }

        // RUNNING stage
        while(stage == RUNNING || stage == START){
            // When process is running -> it might stop due to many reasons
            // Ex: breakpoint ptrace(PTRACE_SINGLESTEP) or terminated
            if(stage == RUNNING){
                if(waitpid(child, &childStatus, 0) < 0) errquit("waitpid");

            }else if(stage == START){
                // stage START can pass waitpid since it is definitely stopped
                // this operation only trigger once -> change stage back to RUNNING
                stage = RUNNING;
            }

            if(WIFSTOPPED(childStatus)){
                // check if stopped by self defined breakpoint 
                // TODO
                    // 0. recover breakpoint command
                    
                    // 1. reset rip(-=1)
                    
                    // 2. show relative message

                // child process is stopped -> We can send our command to child process
                char input[INPUTSIZE] = {};
                fprintf(stderr, "sdb> ");
                fgets(input, INPUTSIZE, stdin);
                char *command = strtok(input, delima);
                struct user_regs_struct regs;

                // Parsing
                if (strncmp(command, "help", INPUTSIZE) == 0 || strncmp(command, "h", INPUTSIZE) == 0){
                    fprintf(stderr, "%s", helpMsg);
                    stage = START; // do nothing to make tracee stop again
                    
                }else if (strncmp(command, "exit", INPUTSIZE) == 0 || strncmp(command, "q", INPUTSIZE) == 0){
                    exit(0);

                }else if (strncmp(command, "list", INPUTSIZE) == 0 || strncmp(command, "l", INPUTSIZE) == 0){
                    checkBreakpoint();
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "run", INPUTSIZE) == 0 || strncmp(command, "r", INPUTSIZE) == 0){
                    fprintf(stderr, "** program %s is already running\n", executable);
                    ptrace(PTRACE_CONT, child, 0, 0);

                }else if (strncmp(command, "break", INPUTSIZE) == 0 || strncmp(command, "b", INPUTSIZE) == 0){
                    // get target address
                    char *target = strtok(NULL, delima);
                    unsigned long long address = strtoll(target, NULL, 16);

                    // 0. update breakpoints
                    addBreakpoint(child, address, lowBound, highBound);
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "cont", INPUTSIZE) == 0 || strncmp(command, "c", INPUTSIZE) == 0){
                    // just keep executing
                    ptrace(PTRACE_CONT, child, 0, 0);

                }else if (strncmp(command, "delete", INPUTSIZE) == 0){
                    // TODO
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "disasm", INPUTSIZE) == 0 || strncmp(command, "d", INPUTSIZE) == 0){
                    // get target address
                    char *target = strtok(NULL, delima);
                    if(target != NULL){
                        int codeIndex = 0;
                        unsigned long long address = strtoll(target, NULL, 16);
                        unsigned long long commandAddress = address;
                        if(address < lowBound || address > highBound){
                            fprintf(stderr,"** the address is out of the range of the text segment\n");

                        }else{
                            long ret;
                            unsigned char *ptr = (unsigned char *)&ret;
                            // 0. get object code
                            for (int i = 0; i < DUMPTIMES; i++){
                                // get machine code at address
                                ret = ptrace(PTRACE_PEEKTEXT, child, address, 0);

                                // save machine code of int to printableASCII
                                for (int j = 0; j < 8; j++){
                                    codeBuf[codeIndex] = ptr[j];
                                    codeIndex++;
                                }
                                address += 8;
                            }

                            // TODO 1. recover from cc to original command

                            // 2. call disasm to print disassemble message
                            disasm((uint8_t *)codeBuf, codeIndex, commandAddress, lowBound, highBound);

                            // 3. reset codeBuf && codeIndex
                            memset(codeBuf, 0, MAX_CHAR_PERINS * MAX_DISASM_INS * sizeof(char));
                            codeIndex = 0;
                        }
                    }else{
                        // Invalid address
                        fprintf(stderr,"** no addr is given\n");
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "dump", INPUTSIZE) == 0 || strncmp(command, "x", INPUTSIZE) == 0){
                    int printableIndex =0;
                    unsigned int printableASCII[DBYTE+1] = {};
                    char *target = strtok(NULL, delima);
                    long ret;
                    unsigned char *ptr = (unsigned char *)&ret;

                    if(target != NULL){
                        unsigned long long address = strtoll(target, NULL, 16);
                        for (int i = 0; i < DUMPTIMES; i++){
                            // get machine code at address
                            ret = ptrace(PTRACE_PEEKTEXT, child, address, 0);

                            // save machine code of int to printableASCII
                            for (int j = 0; j < 8; j++){
                                printableASCII[printableIndex] = (int)ptr[j];
                                printableIndex++;
                            }

                            // even i will print front part
                            if(i%2 ==0){
                                fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x",
                                        address,
                                        ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
                            }else{
                                // odd i will print end part
                                fprintf(stderr, " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x |",
                                    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
                                
                                // print printable ASCII
                                for (int k = 0; k < printableIndex; k++){
                                    if (printableASCII[k] >= 32 && printableASCII[k] <= 127){
                                        // printable
                                        fprintf(stderr,"%c", printableASCII[k]);
                                    }else{
                                        // not printable
                                        fprintf(stderr,".");
                                    }
                                }
                                fprintf(stderr,"|\n");

                                // even + odd = one pair => reset index
                                printableIndex = 0;
                            }
                            address += 8;
                        }

                    }else{
                        // Invalid address
                        fprintf(stderr,"** no addr is given\n");
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "get", INPUTSIZE) == 0 || strncmp(command, "g", INPUTSIZE) == 0){
                    // keep spliting
                    command = strtok(NULL, delima);
                    if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                        printRegs(command, regs);
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "getregs", INPUTSIZE) == 0){
                    if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                        printRegs("all", regs);
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "vmmap", INPUTSIZE) == 0 || strncmp(command, "m", INPUTSIZE) == 0){
                    // 0. get target file string
                    char targetFile[INPUTSIZE] = {};
                    char *address = NULL ;
                    char *perms = NULL ;
                    char *offset = NULL ;
                    char *pathName = NULL ;
                    sprintf(targetFile, "/proc/%d/maps", child);

                    // 1. get information
                    char mapsInfo[MAPSSIZE] = {};
                    FILE* mapsStream = fopen(targetFile, "r");
                    while(fgets(mapsInfo, MAPSSIZE, mapsStream) != NULL){
                        // pasing each line of maps
                        address = strtok(mapsInfo, " \n");
                        perms = strtok(NULL, " \n");
                        offset = strtok(NULL, " \n");
                        strtok(NULL, " \n"); // unused dev
                        strtok(NULL, " \n"); // unused inode
                        pathName = strtok(NULL, " \n");

                        // address Front && End
                        char *addressFront = strtok(address, "-\n");
                        char *addressEnd = strtok(NULL, "-\n");

                        // perms without p
                        perms = strtok(perms, "p");
                        
                        // print result
                        char padding[DBYTE] = {};
                        if(pathName != NULL){
                            fprintf(stderr, "%s%s-%s%s %s %-8s %s\n", addLackZero(padding, addressFront), addressFront, addLackZero(padding, addressEnd), addressEnd, perms, offsetHandling(offset), pathName);
                        }
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "set", INPUTSIZE) == 0 || strncmp(command, "s", INPUTSIZE) == 0){
                    // keep spliting
                    char *targetReg = strtok(NULL, delima);
                    char *value = strtok(NULL, delima);

                    // 0. get original regs
                    if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                        // 1. set reg values
                        setRegs(child, targetReg, value, &regs);
                    }
                    stage = START; // do nothing to make tracee stop again

                }else if (strncmp(command, "si", INPUTSIZE) == 0){
                    // just send single step to tracee
                    ptrace(PTRACE_SINGLESTEP, child, 0, 0);

                }else{
                    fprintf(stderr, "** Invalid command at RUNNING stage: %s\n", input);
                    stage = START; // in order to loop to the same place
                }

            }else if(WIFEXITED(childStatus)){
                // process is finished
                // 1. print message
                fprintf(stderr, "child process %d terminiated normally (code %d)\n", child, childStatus);

                // 2. reload process
                if ((child = fork()) < 0){
                    errquit("fork");
                }

                if (child == 0){ // Child
                    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
                        errquit("ptrace");
                    }
                    execlp(executable, executable, NULL);
                    errquit("execlp");

                }else{ // Parent
                    if (waitpid(child, &childStatus, 0) < 0){
                        errquit("waitpid");
                    }
                    assert(WIFSTOPPED(childStatus));
                    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
                }

                // 3. change stage to LOADED
                stage = LOADED;

            }else{
                errquit("Not STOP or EXIT");
            }
        }
    }
}

//******************************//
//          functions           //
//******************************//
void checkBreakpoint(){
    for(int i=0; i<breakpoints.num; i++){
        fprintf(stderr,"  %d: %llx\n", i, breakpoints.breakpointAddress[i]);
    }
}
void addBreakpoint(pid_t child, unsigned long long address, unsigned long int lowBound, unsigned long int highBound){
    // 0. check if address is within (lowBound,highBound]
    if(address > lowBound && address <= highBound){
        // Note: might save the code having 0xcc => but that is useless => only use last byte to recover code
        // 1. record the address && original command && num of breakpoints
        long code = ptrace(PTRACE_PEEKTEXT, child, address, 0);
        breakpoints.breakpointAddress[breakpoints.num] = address;
        breakpoints.originalCommand[breakpoints.num] = code;
        breakpoints.num ++;

        fprintf(stderr, "** saved code is: 0x%lx\n",code);

        // 2. use ptrace to poke the corresponding memory
        if (ptrace(PTRACE_POKETEXT, child, address,(code & 0xffffffffffffff00) | 0xcc) != 0) errquit("poketext");
        
    }else{
        // Invalid address
        fprintf(stderr,"** the address is out of the range of the text segment\n");
    }
}
void rmBreakpoint(pid_t child, int index){
    // TODO
    // Note: 
    // #0 you can only recover the byte changed to 0xcc (Don't affect the other breakpoint)
    // #1 the last byte of breakpoints.originalCommand is truth -> other bytes are useless and maybe wrong
    // #2 thus, before recover, need to PEEKTEXT again and recover the appointed byte only

    // 0. check if index exist
    if(breakpoints.breakpointAddress[index] != 0){
        // 1. PEEKTEXT again to get code now

        // 2. use ptrace to recover code original command

        // 3. rm the corresponding breakpoint address && command && number of breakpoints

        // 4. tidy up breakpoints
    }else{
        // Invalid index
    }
}
void disasm(uint8_t *code, size_t codeSize, uint64_t startAddress, unsigned long int lowBound, unsigned long int highBound){
    int maxLines = 10;
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open");
    size_t count = cs_disasm(handle, code, codeSize, startAddress, 0, &insn);
    if (count > 0){
        for (size_t j = 0; j < count; j++){
            int lackFillSpace = 32;
            if(maxLines > 0 && insn[j].address >= lowBound && insn[j].address <= highBound){
                // print address
                fprintf(stderr, "\t%" PRIx64 ":", insn[j].address);

                // print machine bytes
                for (int k = 0; k < insn[j].size; k++){
                    fprintf(stderr," %02x", insn[j].bytes[k]);
                    lackFillSpace -=3;
                }
                // print lack space
                for(int m=0; m < lackFillSpace; m++){
                    fprintf(stderr, " ");
                }

                // print disassemble code
                fprintf(stderr, "%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
                maxLines -- ;

            }else{
                fprintf(stderr, "** the address is out of the range of the text segment\n");
                break;
            }
        }
        cs_free(insn, count);
    }else{
        errquit("Fail to disassemble given code");
    }
    cs_close(&handle);
}
int findTextIndex(char *fname, size_t size) {
    int result = -1;
    int fd = open(fname, O_RDONLY);
    char *p = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)p;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;

    for (int i = 0; i < shnum; ++i){
        if(strcmp(sh_strtab_p + shdr[i].sh_name,".text") == 0){
            // find .text && record the index
            result = shdr[i].sh_name;
            break;
        }
    }
    return result;
}
void setRegs(pid_t child, char* target, char *value, struct user_regs_struct *regs){
    // 0. parsing value to unsingned long long
    unsigned long long targetValue = (unsigned long long)strtoll(value,NULL,16);

    // 1. change target reg value
    if(strncmp(target, "rax", INPUTSIZE) == 0){
        regs->rax = targetValue;

    }else if(strncmp(target, "rbx", INPUTSIZE) == 0){
        regs->rbx = targetValue;

    }else if(strncmp(target, "rcx", INPUTSIZE) == 0){
        regs->rcx = targetValue;

    }else if(strncmp(target, "rdx", INPUTSIZE) == 0){
        regs->rdx = targetValue;

    }else if(strncmp(target, "r8", INPUTSIZE) == 0){
        regs->r8 = targetValue;

    }else if(strncmp(target, "r9", INPUTSIZE) == 0){
        regs->r9 = targetValue;

    }else if(strncmp(target, "r10", INPUTSIZE) == 0){
        regs->r10 = targetValue;

    }else if(strncmp(target, "r11", INPUTSIZE) == 0){
        regs->r11 = targetValue;

    }else if(strncmp(target, "r12", INPUTSIZE) == 0){
        regs->r12 = targetValue;

    }else if(strncmp(target, "r13", INPUTSIZE) == 0){
        regs->r13 = targetValue;

    }else if(strncmp(target, "r14", INPUTSIZE) == 0){
        regs->r14 = targetValue;

    }else if(strncmp(target, "r15", INPUTSIZE) == 0){
        regs->r15 = targetValue;

    }else if(strncmp(target, "rdi", INPUTSIZE) == 0){
        regs->rdi = targetValue;

    }else if(strncmp(target, "rsi", INPUTSIZE) == 0){
        regs->rsi = targetValue;

    }else if(strncmp(target, "rbp", INPUTSIZE) == 0){
        regs->rbp = targetValue;

    }else if(strncmp(target, "rsp", INPUTSIZE) == 0){
        regs->rsp = targetValue;

    }else if(strncmp(target, "rip", INPUTSIZE) == 0){
        regs->rip = targetValue;

    }else if(strncmp(target, "flags", INPUTSIZE) == 0){
        regs->eflags = targetValue;

    }else{
        fprintf(stderr, "** unknown target in setRegs\n");
        return ;
    }

    // 2. call ptrace to update value 
    if (ptrace(PTRACE_SETREGS, child, 0, regs) != 0) errquit("ptrace(SETREGS)");
}
char* offsetHandling(char *offset){
    int length = strlen(offset);
    for(int i=0; i<length;i++){
        if(offset[i] != '0'){
            offset = &offset[i];
            break;

        }else if(i == length-1){
            // last one
            offset = &offset[i];
        }
    }
    return offset;
}
char* addLackZero(char *padding,char *target){
    memset(padding,0,DBYTE);

    int length = strlen(target);
    int lack = DBYTE - length;
    for(int i=0;i<lack;i++){
        strcat(padding,"0");
    }
    return padding;
}
void printRegs(char* target, struct user_regs_struct regs){
    unsigned long long rax = regs.rax;
    unsigned long long rbx = regs.rbx;
    unsigned long long rcx = regs.rcx;
    unsigned long long rdx = regs.rdx;

    unsigned long long r8 = regs.r8;
    unsigned long long r9 = regs.r9;
    unsigned long long r10 = regs.r10;
    unsigned long long r11 = regs.r11;

    unsigned long long r12 = regs.r12;
    unsigned long long r13 = regs.r13;
    unsigned long long r14 = regs.r14;
    unsigned long long r15 = regs.r15;

    unsigned long long rdi = regs.rdi;
    unsigned long long rsi = regs.rsi;
    unsigned long long rbp = regs.rbp;
    unsigned long long rsp = regs.rsp;

    unsigned long long rip = regs.rip;
    unsigned long long eflags = regs.eflags;

    if(strncmp(target, "all", INPUTSIZE) ==0){
        // print all
        fprintf(stderr,"RAX %-16llx  RBX %-16llx  RCX %-16llx  RDX %llx\n", rax, rbx, rcx, rdx);
        fprintf(stderr,"R8  %-16llx  R9  %-16llx  R10 %-16llx  R11 %llx\n", r8, r9, r10, r11);
        fprintf(stderr,"R12 %-16llx  R13 %-16llx  R14 %-16llx  R15 %llx\n", r12, r13, r14, r15);
        fprintf(stderr,"RDI %-16llx  RSI %-16llx  RBP %-16llx  RSP %llx\n", rdi, rsi, rbp, rsp);
        fprintf(stderr,"RIP %-16llx  FLAGS %016llx\n", rip, eflags);
    }else{
        if (strncmp(target, "rax", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rax, rax);
        }else if (strncmp(target, "rbx", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rbx, rbx);
        }else if (strncmp(target, "rcx", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rcx, rcx);
        }else if (strncmp(target, "rdx", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rdx, rdx);
        }else if (strncmp(target, "r8", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r8, r8);
        }else if (strncmp(target, "r9", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r9, r9);
        }else if (strncmp(target, "r10", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r10, r10);
        }else if (strncmp(target, "r11", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r11, r11);
        }else if (strncmp(target, "r12", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r12, r12);
        }else if (strncmp(target, "r13", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r13, r13);
        }else if (strncmp(target, "r14", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r14, r14);
        }else if (strncmp(target, "r15", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, r15, r15);
        }else if (strncmp(target, "rdi", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rdi, rdi);
        }else if (strncmp(target, "rsi", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rsi, rsi);
        }else if (strncmp(target, "rbp", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rbp, rbp);
        }else if (strncmp(target, "rsp", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rsp, rsp);
        }else if (strncmp(target, "rip", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, rip, rip);
        }else if (strncmp(target, "flags", INPUTSIZE) == 0){
            fprintf(stderr,"%s = %lld (0x%llx)\n",target, eflags, eflags);
        }else{
            fprintf(stderr,"** unknown target in printRegs\n");
        }
    }
}
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}
void handleScriptPath(int argc, char* argv[], char* scriptPath){
    char option = '\0';
    while((option = getopt(argc,argv,"s:")) != -1){
        switch(option){
            case 's':
                strcat(scriptPath, optarg);
                break;
            default:
                fprintf(stderr,"usage: ./hw4 [-s script] [program]\n");
                exit(-1);
        }
    }    
}
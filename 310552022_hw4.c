#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/user.h>
#include <errno.h>

//******************************//
//        Global Define         //
//******************************//
#define INPUTSIZE 256
char helpMsg[] = "- break {instruction-address}: add a break point\n- cont: continue execution\n- delete {break-point-id}: remove a break point\n- disasm addr: disassemble instructions in a file or a memory region\n- dump addr: dump memory content\n- exit: terminate the debugger\n- get reg: get a single value from a register\n- getregs: show registers\n- help: show this message\n- list: list break points\n- load {path/to/a/program}: load a program\n- run: run the program\n- vmmap: show memory layout\n- set reg val: get a single value to a register\n- si: step into instruction\n- start: start the program and stop at the first instruction\n";
const char delima[3] = " \n";
typedef enum{
    NOTLOADED,
    LOADED,
    RUNNING
}stage_t;

//******************************//
//          functions           //
//******************************//
void errquit(const char *msg);
void handleScriptPath(int argc, char* argv[], char* scriptPath);

//******************************//
//             main             //
//******************************//
int main(int argc, char* argv[]){
    stage_t stage = NOTLOADED;
    pid_t child;
    int childStatus;

    long ret;
    unsigned long long rip;
    struct user_regs_struct regs;
    unsigned char *ptr = (unsigned char *)&ret;

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
    printf("** scriptPath: %s\n",scriptPath);
    printf("** executable file: %s\n",executable);
    
    // if hasExecutable -> load exe first 
    if(hasExecutable){
        if ((child = fork()) < 0){
            errquit("fork");
        }
            
        if (child == 0){ // Child
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
                errquit("ptrace");
            }
            execlp(executable, executable, NULL);
            errquit("execvp");

        }else{ // Parent
            if (waitpid(child, &childStatus, 0) < 0){
                errquit("waitpid");
            }
            assert(WIFSTOPPED(childStatus));
            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

            // Get child entry point and data
            if ((rip = ptrace(PTRACE_PEEKUSER, child, ((unsigned char *)&regs.rip) - ((unsigned char *)&regs), 0)) != 0){
                ret = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
            }else{
                perror("ptrace(PTRACE_PEEKUSER)");
            }
            // Show relative infomation
            printf("** program \'%s\' loaded. entry point 0x%llx\n", executable, rip);
        }
        stage = LOADED;
    }

    // NOTLOADED stage 
    while(stage == NOTLOADED){
        char input[INPUTSIZE] = {};
        printf("sdb> ");
        fgets(input,INPUTSIZE,stdin);
        char *command = strtok(input, delima);

        // Parsing
        if(strncmp(command,"help",INPUTSIZE) == 0 || strncmp(command,"h",INPUTSIZE) ==0){
            printf("%s",helpMsg);

        }else if(strncmp(command,"exit",INPUTSIZE) == 0 || strncmp(command,"q",INPUTSIZE) ==0){
            exit(0);

        }else if(strncmp(command,"list",INPUTSIZE) == 0 || strncmp(command,"l",INPUTSIZE) ==0){


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
                errquit("execvp");
            }else{ // Parent
                if (waitpid(child, &childStatus, 0) < 0){
                    errquit("waitpid");
                }
                assert(WIFSTOPPED(childStatus));
                ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

                // Get child entry point and data
                if ((rip = ptrace(PTRACE_PEEKUSER, child, ((unsigned char *)&regs.rip) - ((unsigned char *)&regs), 0)) != 0){
                    ret = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
                }else{
                    perror("ptrace(PTRACE_PEEKUSER)");
                }
                // Show relative infomation
                printf("** program \'%s\' loaded. entry point 0x%llx\n", executable, rip);
            }
            stage = LOADED;

        }else{
            printf("** Invalid command: %s\n",input);
        }
    }
    /*
    // debugger keep working
    while(1){
        // LOADED stage
        while (stage == LOADED){
        
        }

        // RUNNING stage
        while(stage == RUNNING){

        }
    }
    */
}

//******************************//
//          functions           //
//******************************//
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
                printf("usage: ./hw4 [-s script] [program]\n");
                exit(-1);
        }
    }    
}
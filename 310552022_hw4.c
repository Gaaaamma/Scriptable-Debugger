#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

//******************************//
//        Global Define         //
//******************************//
#define INPUTSIZE 256
char helpMsg[] = "** - break {instruction-address}: add a break point\n** - cont: continue execution\n** - delete {break-point-id}: remove a break point\n** - disasm addr: disassemble instructions in a file or a memory region\n** - dump addr: dump memory content\n** - exit: terminate the debugger\n** - get reg: get a single value from a register\n** - getregs: show registers\n** - help: show this message\n** - list: list break points\n** - load {path/to/a/program}: load a program\n** - run: run the program\n** - vmmap: show memory layout\n** - set reg val: get a single value to a register\n** - si: step into instruction\n** - start: start the program and stop at the first instruction\n";
typedef enum{
    NOTLOADED,
    LOADED,
    RUNNING
}stage_t;

//******************************//
//          functions           //
//******************************//
void handleScriptPath(int argc, char* argv[], char* scriptPath);

//******************************//
//             main             //
//******************************//
int main(int argc, char* argv[]){
    stage_t stage = NOTLOADED;
    int hasScript, hasExecutable=0;
    char scriptPath[100] = {};
    char executable[100] = {};
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
    
    // load exe first 
    if(hasExecutable){
        
        stage = LOADED;
    }

    // if not loaded stage 
    while(stage == NOTLOADED){
        char input[INPUTSIZE] = {};
        printf("sdb> ");
        scanf("%s",input);
        
        // Parsing
        if(strncmp(input,"help",INPUTSIZE) == 0 || strncmp(input,"h",INPUTSIZE) ==0){
            printf("%s",helpMsg);

        }else if(strncmp(input,"exit",INPUTSIZE) == 0 || strncmp(input,"q",INPUTSIZE) ==0){
            exit(0);

        }else if(strncmp(input,"list",INPUTSIZE) == 0 || strncmp(input,"l",INPUTSIZE) ==0){


        }else if(strncmp(input,"load",INPUTSIZE) == 0){

            stage = LOADED;
        }else{
            printf("** Invalid command: %s\n",input);

        }
    }
}

//******************************//
//          functions           //
//******************************//
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
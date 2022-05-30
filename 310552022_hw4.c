#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void handleScriptPath(int argc, char* argv[], char* scriptPath);

int main(int argc, char* argv[]){
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
    printf("scriptPath: %d %s\n",hasScript,scriptPath);
    printf("executable file: %d %s\n",hasExecutable,executable);
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
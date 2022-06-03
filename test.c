#include <stdio.h>
void testFun(){
    char a = 'a';
    char b = 'b';
    char c = 'c';
    char d = 'd';
    printf("testFun() is done\n");
    return;
    
}

int main(int argc, char* argv[]){
    int a = 1;
    char b = 'b';
    int c = 3;
    testFun();
    int d = 4;
    int e = a + c -d ;
    printf("test.c is done\n");
}
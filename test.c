#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>

//#define CODE "\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00"
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void disasm(uint8_t *code, size_t codeSize, uint64_t startAddress){
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open");
    size_t count = cs_disasm(handle, code, codeSize, startAddress, 0, &insn);
    if (count > 0){
        size_t j;
        for (j = 0; j < count; j++){
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
			for(int k=0;k<insn[j].size;k++){
				printf("%02x ",insn[j].bytes[k]);
			}
			printf("\n");
        }

        cs_free(insn, count);
    }else{
        errquit("Fail to disassemble given code");
    }
    cs_close(&handle);
}

int main(int argc, char *argv[]){
	// char buf[100]={};
	// char *buf = "\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00";
	
	unsigned char *buf = (unsigned char*)malloc(100 * sizeof(char));
	buf[0] = 184;
	buf[1] = 4;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 187;
	buf[6] = 1;
	buf[7] = 0;
	buf[8] = 0;
	buf[9] = 0;		
	disasm((uint8_t *)buf,10,0x4000b0);
}
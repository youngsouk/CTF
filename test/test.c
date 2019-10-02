#include <stdio.h>

int main(){
	char * buf = malloc(0x100);
	malloc(20);
	free(buf);
}


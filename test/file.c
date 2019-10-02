#include <stdio.h>
#include <stdlib.h>
#include "libioP.h"

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

int main(){
	FILE *f = 0;
	
	printf("%p\n", sizeof(_IO_FILE));
	printf("%p\n", (void *)&((_IO_FILE *)0) -> _vtable_offset);
	printf("%p\n", (void *)&((_IO_FILE_plus *)0) -> vtable);
}

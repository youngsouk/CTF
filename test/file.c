#include <stdio.h>
#include <stdlib.h>


int main(){
	FILE *f = 0;
	
	printf("%p\n", sizeof(_IO_FILE));
	printf("%p\n", &((_IO_FILE *)0) -> _vtable_offset);
}

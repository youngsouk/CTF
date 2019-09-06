#include <stdio.h>

int main(){
	_IO_FILE *t= 0;

	printf("%d\n", (size_t)t + sizeof(_IO_FILE));
}

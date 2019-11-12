#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
	void * p = malloc(200);
	malloc(10);
	free(p);
	malloc(10);
}

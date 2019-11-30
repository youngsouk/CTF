#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x50);
  
  free(p1);
  malloc(0x400);
  free(p1);

  free(p2);
  malloc(0x400);
  free(p2);
  
  malloc(0x40);
  printf("%p\n", malloc(0x40));
}

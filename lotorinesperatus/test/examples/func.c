#include <stdio.h>

int func(long long int x) {
  for (int i = 0; i < 20; i++) {
    x = x + i;
  }
  return (int)x;
}

int main(void) {
  printf("f %d\n", func((long long int)100));
  return 0;
}

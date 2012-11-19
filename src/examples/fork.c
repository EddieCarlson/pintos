#include <syscall.h>
#include <stdio.h>
#include "/homes/iws/knappg/pintos/src/tests/lib.h"
#include "/homes/iws/knappg/pintos/src/tests/main.h"

int
main (int argc, char **argv)
{
  // int pid = fork();
  // printf("pid: %d\n", pid);
  // if (pid == 0) {
  //   if (fork() == 0) {
  //     if (fork() == 0) {
  //       fork();
  //     }
  //   }
  // }
  // return EXIT_SUCCESS;
  int depth = 3;
  int total = 0;

  while (depth > 0) {
      total += depth;
      if (fork() == -1) {
          printf("fail %d", depth);
      }
      depth--;
  }
  printf("%d\n", total);
  return EXIT_SUCCESS;
    
}
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/file.h"

// Awkward size to compensate for the naivety of malloc
#define FD_BUF_SIZE 244

struct fd {
  int fd;
  struct file *f;
  struct list_elem fd_elem;
  struct fd_buffer *buf;
};

struct fd_buffer {
  int ref_count;
  char fd_buf[FD_BUF_SIZE];
  int first;
  int last;
};

void syscall_init (void);

#endif /* userprog/syscall.h */

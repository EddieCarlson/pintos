#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/interrupt.h"

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
  struct lock buf_lock;
};

struct fork_args {
  uint32_t *pagedir;
  uint32_t *parent_stack;
};

void syscall_init (void);
void exit_fail(struct intr_frame *f);

#endif /* userprog/syscall.h */

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "devices/shutdown.h"

#define WORD_SIZE sizeof(void *)
#define SUPPORTED_ARGS 3
#define MAX_WRITE_STDOUT_SIZE 128

struct arguments {
  void *args[SUPPORTED_ARGS];
};

static void syscall_handler (struct intr_frame *);
static void populate_arg_struct(struct intr_frame *f, struct arguments *args, int num_args);

// 0 argument sys_calls
static void sys_halt_handler(void);
static void sys_fork_handler(void);

// 1 argument sys_calls
static void sys_exit_handler(struct arguments *args);
static void sys_pipe_handler(struct arguments *args);
static void sys_exec_handler(struct arguments *args);
static void sys_wait_handler(struct arguments *args);
static int sys_open_handler(struct arguments *args);
static void sys_tell_handler(struct arguments *args);
static void sys_close_handler(struct arguments *args);
static uint32_t sys_filesize_handler(struct arguments *args);

// 2 argument sys_calls
static void sys_dup2_handler(struct arguments *args);

// 3 argument sys_calls
static void sys_read_handler(struct arguments *args);
static uint32_t sys_write_handler(struct arguments *args);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_number = *((int *) f->esp);
  struct arguments args;
  populate_arg_struct(f, &args, SUPPORTED_ARGS);

	switch (syscall_number) {
    case SYS_HALT:
      sys_halt_handler();
      break;
    case SYS_FORK:
      sys_fork_handler();
      break;
    case SYS_EXIT:
      thread_exit();
      sys_exit_handler(&args);
      break;
    case SYS_PIPE:
      sys_pipe_handler(&args);
      break;
    case SYS_EXEC:
      sys_exec_handler(&args);
      break;
    case SYS_WAIT:
      sys_wait_handler(&args);
      break;
    case SYS_OPEN:
      f->eax = sys_open_handler(&args);
      break;
    case SYS_TELL:
      sys_tell_handler(&args);
      break;
    case SYS_CLOSE:
      sys_close_handler(&args);
      break;
    case SYS_FILESIZE:
      f->eax = sys_filesize_handler(&args);
      break;
    case SYS_DUP2:
      sys_dup2_handler(&args);
      break;
    case SYS_READ:
      sys_read_handler(&args);
      break;
    case SYS_WRITE:
      f->eax = sys_write_handler(&args);
      break;
  }

  //asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (f) : "memory");
}

static void populate_arg_struct(struct intr_frame *f, struct arguments *args, int num_args) {
  int i;
  for (i = 1; i <= num_args; i++) {
    args->args[i - 1] = f->esp + WORD_SIZE * i;
  }
}

static void sys_halt_handler(void) {
  shutdown_power_off();
}

static void sys_fork_handler(void) {

}

static void sys_exit_handler(struct arguments *args) {

}

static void sys_pipe_handler(struct arguments *args) {

}

static void sys_exec_handler(struct arguments *args) {

}

static void sys_wait_handler(struct arguments *args) {

}

static int sys_open_handler(struct arguments *args) {
  char *file_name = *((char **) args->args[0]);
  struct file *f = filesys_open(file_name);

  if (f == NULL) {
    return -1;
  }

  struct thread *cur_thread = thread_current();
  struct fd *file_desc = (struct fd *) malloc(sizeof(struct fd));
  file_desc->fd = cur_thread->next_fd;
  (cur_thread->next_fd)++;
  file_desc->f = f;
  file_desc->buf = NULL;

  list_push_back(&cur_thread->fd_list, &file_desc->fd_elem);
  return file_desc->fd;
}

static void sys_tell_handler(struct arguments *args) {

}

static void sys_close_handler(struct arguments *args) {
  int fd = ((int *) args->args[0]);

  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    struct fd *file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      list_remove(e);
      if (file_desc->buf == NULL) {
        file_close(file_desc->f);
      } else {
        (file_desc->buf->ref_count)--;
        if (file_desc->buf->ref_count == 0) {
          free(file_desc->buf);
        }
      }
      free(file_desc);
      break; 
    }
  }
}
static uint32_t sys_filesize_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);

  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    struct fd *file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      if (file_desc->buf == NULL) {
        return file_length(file_desc->f);
      }
      break; 
    }
  }

  return 0;
}
static void sys_dup2_handler(struct arguments *args) {

}
static void sys_read_handler(struct arguments *args) {

}
static uint32_t sys_write_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);
  void *buf = *((void **) args->args[1]);
  uint32_t size = *((uint32_t *) args->args[2]);

  if (fd == 1) {
    if (size > MAX_WRITE_STDOUT_SIZE) {
      putbuf((char *) buf, MAX_WRITE_STDOUT_SIZE);
      return MAX_WRITE_STDOUT_SIZE;
    } else {
      putbuf((char *) buf, size);
      return size;
    }
  }

  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    struct fd *file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      if (file_desc->buf == NULL && !(file_desc->f->deny_write)) {
        return (uint32_t) file_write(file_desc->f, buf, size);
      }
      break; 
    }
  }

  return 0;
}
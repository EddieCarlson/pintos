#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include <list.h>
#include <string.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/synch.h"
#include "vm/frame.h"

#define WORD_SIZE sizeof(void *)
#define SUPPORTED_ARGS 3
#define MAX_WRITE_STDOUT_SIZE 128

struct arguments {
  void *args[SUPPORTED_ARGS];
};
static thread_func build_fork NO_RETURN;

static struct lock filesys_lock;

static bool validate_ptr(void * ptr);

static void syscall_handler (struct intr_frame *);
static void populate_arg_struct(struct intr_frame *f, struct arguments *args, int num_args);

// 0 argument sys_calls
static void sys_halt_handler(void);
static tid_t sys_fork_handler(struct intr_frame *f);

// 1 argument sys_calls
static void sys_exit_handler(struct arguments *args);
static int sys_pipe_handler(struct arguments *args); 
static void sys_exec_handler(struct arguments *args);
static int sys_wait_handler(struct arguments *args);
static int sys_open_handler(struct arguments *args);
static off_t sys_tell_handler(struct arguments *args); 
static void sys_close_handler(struct arguments *args);
static uint32_t sys_filesize_handler(struct arguments *args);
static bool sys_remove_handler (struct arguments *args);

// 2 argument sys_calls
static int sys_dup2_handler(struct arguments *args);
static bool sys_create_handler (struct arguments *args);

// 3 argument sys_calls
static int sys_read_handler(struct arguments *args);
static uint32_t sys_write_handler(struct arguments *args); ///?

static bool validate_ptr(void * ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(!(validate_ptr(f->esp))){
    struct arguments bad_args;
    int i = -1;
    bad_args.args[0] = (void *) &i;
    sys_exit_handler(&bad_args);
  }

  int syscall_number = *((int *) f->esp);
  struct arguments args;
  populate_arg_struct(f, &args, SUPPORTED_ARGS);

	switch (syscall_number) {
    case SYS_HALT:
      sys_halt_handler();
      break;
    case SYS_FORK:
      f->eax = sys_fork_handler(f);
      break;
    case SYS_EXIT:
      sys_exit_handler(&args);
      break;
    case SYS_PIPE:
      f->eax = sys_pipe_handler(&args);
      break;
    case SYS_EXEC:
      sys_exec_handler(&args);
      break;
    case SYS_WAIT:
      f->eax = sys_wait_handler(&args);
      break;
    case SYS_OPEN:
      if(!(validate_ptr( *((char **)args.args[0]) ))) {
        exit_fail(f);
      } else {
        f->eax = sys_open_handler(&args);
        break;
      }
    case SYS_TELL:
      f->eax = sys_tell_handler(&args);
      break;
    case SYS_CLOSE:
      sys_close_handler(&args);
      break;
    case SYS_FILESIZE:
      f->eax = sys_filesize_handler(&args);
      break;
    case SYS_DUP2:
      f->eax = sys_dup2_handler(&args);
      break;
    case SYS_READ:
     if(!(validate_ptr( *((char **)args.args[1]) ))) {
        exit_fail(f);
      } else{
        f->eax = sys_read_handler(&args);
        break;
      }
    case SYS_WRITE:
     if(!(validate_ptr( *((char **)args.args[1]) ))) {
        exit_fail(f);
      } else{
        f->eax = sys_write_handler(&args);
        break;
      }
    case SYS_CREATE:
      if(!(validate_ptr( *((char **)args.args[1]) ))) {
        exit_fail(f);
      } else {
        f->eax = sys_create_handler(&args);
        break; 
      }
    case SYS_REMOVE:
      if(!(validate_ptr( *((char **)args.args[1]) ))) {
        exit_fail(f);
      } else {
        f->eax = sys_remove_handler(&args);
        break; 
      }
  }
}

void exit_fail(struct intr_frame *f){
  struct arguments bad_args;
  int i = -1;
  bad_args.args[0] = (void *) &i;
  f->eax = -1;
  sys_exit_handler(&bad_args);
}

static bool validate_ptr(void * ptr){
  if (!(is_user_vaddr(ptr)))
    return false;

  if(pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    return false;

  return true;
}

//Iterates through list of fd, searching for passed fd int
static struct fd *find_file_desc(int fd){
  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    struct fd *file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      return file_desc;
    }
  }

  return NULL;
}

static void populate_arg_struct(struct intr_frame *f, struct arguments *args, int num_args) {
  int i;
  for (i = 1; i <= num_args; i++) {
    void *next_ptr = f->esp + WORD_SIZE * i;
    if(!(validate_ptr(next_ptr))){
      exit_fail(f);
    } else{
      args->args[i - 1] = next_ptr;
    }
  }
}

static void sys_halt_handler(void) {
  shutdown_power_off();
}

static void build_fork(void *args_ UNUSED) {
  struct thread *cur = thread_current();

  lock_acquire(&cur->forking_child_lock);
  while (!cur->ready) {
    cond_wait(&cur->forking_child_cond, &cur->forking_child_lock);
  }
  lock_release(&cur->forking_child_lock);

  process_activate();

  struct intr_frame i_f;
  memcpy(&i_f, &cur->i_f, sizeof(struct intr_frame));
  i_f.eax = 0;

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&i_f) : "memory");
  NOT_REACHED();
}

struct populate_child_args {
  uint32_t *pagedir;
  struct intr_frame *i_f;
  tid_t child_tid;
};

static thread_action_func populate_child;

static void populate_child(struct thread *child, void *args_) {
  struct populate_child_args *args = (struct populate_child_args *) args_;
  struct thread *cur = thread_current();
  if (child->tid == args->child_tid) {
    child->pagedir = args->pagedir;
    memcpy(&child->i_f, args->i_f, sizeof(struct intr_frame));

    struct child_thread_info *child_info = malloc(sizeof(struct child_thread_info));
    child_info->status = -1; // This is the default value, we're very pessimistic..
    child_info->tid = args->child_tid;
    child_info->dead = false; // It's not stillborn
    list_push_back(&(cur->child_list), &(child_info->waiting_list_elem));

    memcpy(&child->name, &cur->name, 16);

    // Wake the child if need be
    lock_acquire(&child->forking_child_lock);
    child->ready = true;
    cond_signal(&child->forking_child_cond, &child->forking_child_lock);
    lock_release(&child->forking_child_lock);
  }
}

static tid_t sys_fork_handler(struct intr_frame *f) {
  struct thread *cur = thread_current();
  struct fork_args args;
  args.parent_stack = (uint32_t *) cur->stack;

  uint32_t *new_pagedir = pagedir_create();
  uint32_t *pde;

  for (pde = cur->pagedir; pde < cur->pagedir + pd_no (PHYS_BASE); pde++) {
    if (*pde & PTE_P) {

      uint32_t *pt = pde_get_pt (*pde);
      uint32_t *pte;
      
      for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++) {
        if (*pte & PTE_P) {
          void *goody = pti_pdi_get_base((uint32_t) (pte - pt), (uint32_t) (pde - cur->pagedir));
          
          void *new_page = frame_alloc();
          void *parent_page = pte_get_page(*pte);
          memcpy(new_page, parent_page, PGSIZE);
          pagedir_set_page(new_pagedir, goody, new_page, true);
        }   
      }
    }
  }
  tid_t child_tid = (tid_t) thread_create(cur->name, cur->priority, &build_fork, &args);

  struct populate_child_args child_args;
  child_args.pagedir = new_pagedir;
  child_args.i_f = f;
  child_args.child_tid = child_tid;

  enum intr_level old_level = intr_disable ();
  thread_foreach(&populate_child, &child_args);
  intr_set_level (old_level);

  return child_tid;
}

static void sys_exit_handler(struct arguments *args) {
  int status = *((int *) args->args[0]);

  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // Need to still return the status to the kernel parent thread...
  thread_exit();
}

static int sys_pipe_handler(struct arguments *args) {
  int *fd = ((int *) args->args[0]);

  struct fd *file_desc1 = (struct fd *) malloc(sizeof(struct fd));
  struct fd *file_desc2 = (struct fd *) malloc(sizeof(struct fd));

  struct thread *cur_thread = thread_current();

  if(file_desc2 == NULL)
    return -1;

  if(file_desc1 == NULL)
    return -1;

  struct fd_buffer *fd_buf = (struct fd_buffer *) malloc(sizeof(struct fd_buffer));
  fd_buf->first = 0;
  fd_buf->last = 0;
  fd_buf->ref_count = 2;
  lock_init(&fd_buf->buf_lock);

  file_desc1->buf = fd_buf;
  file_desc1->fd = cur_thread->next_fd;

  (cur_thread->next_fd)++;

  file_desc2->buf = fd_buf;
  file_desc2->fd = cur_thread->next_fd;

  (cur_thread->next_fd)++;

  fd[0] = file_desc1->fd;
  fd[1] = file_desc2->fd;

  return 0;

}

static void sys_exec_handler(struct arguments *args) {
  char *fn_copy;
     
  fn_copy = frame_alloc();

  char *cmd_line = *((char **) args->args[0]);

  strlcpy(fn_copy, cmd_line, PGSIZE);

  exec_start((void *)fn_copy);
}

static int sys_wait_handler(struct arguments *args) {
  tid_t status = *((tid_t *) args->args[0]);
  return process_wait(status);
}

static int sys_open_handler(struct arguments *args) {
  char *file_name = *((char **) args->args[0]);

  if(file_name == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file_name);
  lock_release(&filesys_lock);

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

static off_t sys_tell_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);

  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    struct fd *file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      if (file_desc->buf == NULL) {
        return (off_t) file_desc->f->pos;
      }
      break; 
    }
  }

  return -1;

}

static void sys_close_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);

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

static int sys_dup2_handler(struct arguments *args) {
  int fd1 = *((int *) args->args[0]);
  int fd2 = *((int *) args->args[1]);

  struct fd *file_desc1 = find_file_desc(fd1);
  struct fd *file_desc2 = find_file_desc(fd2);

  struct thread *cur_thread = thread_current();

  // If oldfd not valid, do nothing
  if(file_desc1 == NULL)
    return -1;

  if(file_desc2 != NULL){
    if(file_desc2->f != NULL)
      file_close(file_desc2->f);
    else{
      (file_desc2->buf->ref_count)--;
      if (file_desc2->buf->ref_count == 0) {
        free(file_desc2->buf);
      }
    }

    if(file_desc1->buf == NULL){
      file_desc2->f = file_desc1->f;

    } else{
      file_desc2->buf = file_desc1->buf;
      file_desc1->buf->ref_count++;
    }
  } else{
    file_desc2 = (struct fd *) malloc(sizeof(struct fd));
    file_desc2->fd = cur_thread->next_fd;
    list_push_back(&cur_thread->fd_list, &file_desc2->fd_elem);
    (cur_thread->next_fd)++;
  }

  return 0;
}

static int sys_read_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);
  char *buf = *((char **) args->args[1]);
  uint32_t size = *((off_t *) args->args[2]);

  if(fd == 0){
    return (off_t) input_getc();
  }

  if(fd == 1)
    return -1;

  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  struct fd *file_desc = NULL;
  bool found = false;

  for (e = list_begin(&cur_thread->fd_list); e != list_end(&cur_thread->fd_list); e = list_next(e)) {
    file_desc = list_entry (e, struct fd, fd_elem);
    if (file_desc->fd == fd) {
      found = true;
      break; 
    }
  }

  if(file_desc == NULL || !found)
    return -1;

  if(file_desc->buf == NULL){
    return (int) file_read(file_desc->f, buf, size);
  } else {
    // It's a buffer, so we'll read as much as we can, and return what that was.
    uint32_t read = 0;
    lock_acquire(&file_desc->buf->buf_lock);
    while (read < size && file_desc->buf->last != file_desc->buf->first) {
      buf[read] = file_desc->buf->fd_buf[file_desc->buf->first];
      file_desc->buf->first++;
      read++;
    }
    lock_release(&file_desc->buf->buf_lock);
    return read;
  }
}

static uint32_t sys_write_handler(struct arguments *args) {
  int fd = *((int *) args->args[0]);
  char *buf = *((char **) args->args[1]);
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
      } else if (file_desc->buf != NULL) {
        // It's a buffer, we will write as much as we can, and then return what that was
        uint32_t written = 0;
        lock_acquire(&file_desc->buf->buf_lock);
        while (written < size && file_desc->buf->last - file_desc->buf->first != FD_BUF_SIZE) {
          file_desc->buf->fd_buf[file_desc->buf->last] = buf[written];
          file_desc->buf->last++;
          written++;
        }
        lock_release(&file_desc->buf->buf_lock);
        return written;
      }
      break; 
    }
  }
  return 0;
}

bool sys_create_handler (struct arguments *args) {
  char *file_name = *((char **) args->args[0]);
  unsigned initial_size = *((unsigned *) args->args[1]);

  lock_acquire(&filesys_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&filesys_lock);

  return success;
}

bool sys_remove_handler (struct arguments *args) {
  char *file_name = *((char **) args->args[0]);

  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file_name);
  lock_release(&filesys_lock);

  return success;
}
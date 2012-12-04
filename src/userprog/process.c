#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"

#define MAX_ARGS 128
#define WORD_SIZE sizeof(void *)

struct arguments {
  int num_args;
  char *args[MAX_ARGS];
};

static thread_func start_process NO_RETURN;
static bool load (struct arguments *args, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

// Our Idea: Tokenize the file_name parameter in process_execute
// so that it now is an array of the arguments. Pass this to start_process
// In load, this will be used to compute the stack offset, and then we will manually
// set the addresses of the arguments under PHYS_BASE (right after the call to setup_stack)
tid_t
process_execute (const char *file_name) 
{
  tid_t tid;
	char *fn_copy;
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
     
  fn_copy = frame_alloc();
  if (fn_copy == NULL)
    return TID_ERROR;
	
	strlcpy(fn_copy, file_name, PGSIZE);

  // Make a copy of the filename for the thread name to avoid modifying the const
  // string
  char temp_name[16];
  memcpy(temp_name, file_name, 16);
	
  //Parse file name from passed file name
  char *saveptr;
  char *cur = strtok_r(temp_name, " ", &saveptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cur, PRI_DEFAULT, start_process, fn_copy);

  // It is now a child of the current thread
  struct child_thread_info *child = malloc(sizeof(struct child_thread_info));
  child->status = -1; // This is the default value, we're very pessimistic..
  child->tid = tid;
  child->dead = false; // It's not stillborn
  list_push_back(&(thread_current()->child_list), &(child->waiting_list_elem));

  if (tid == TID_ERROR)
    frame_free(fn_copy); 
  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{	
	char *fn_copy = args_;
	struct arguments args;

  char *saveptr;
  char *delim = " ";
  char *cur = strtok_r(fn_copy, delim, &saveptr);
  args.num_args = 0;
  while (cur != NULL) {
    args.args[args.num_args] = cur;
    args.num_args++;
    cur = strtok_r(NULL, delim, &saveptr);
  }
	
  memset(thread_current()->name, 0, 16);
  memcpy(thread_current()->name, fn_copy, 16);

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (&args, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  frame_free(args_);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

void exec_start(void *args_){

  start_process(args_);
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur_thread = thread_current();
  lock_acquire(&(cur_thread->waiting_child_lock));
  struct list_elem *e;
  bool found = false;
  struct child_thread_info *child;
  int returned_status;

  // Find child
  for (e = list_begin(&cur_thread->child_list); e != list_end(&cur_thread->child_list); e = list_next(e)) {
    child = list_entry(e, struct child_thread_info, waiting_list_elem);
    if (child->tid == child_tid) {
      found = true;
      break;
    }
  }

  // No child, or already seen it
  if (!found) {
    return -1;
  }

  while (!child->dead) {
    cond_wait(&cur_thread->waiting_for_child, &cur_thread->waiting_child_lock);
  }
  list_remove(&(child->waiting_list_elem));

  returned_status = child->status;
  free(child);

  lock_release(&(cur_thread->waiting_child_lock));

  return returned_status;
}


// Helper functions for iterating over threads in process exit
static thread_action_func mark_dead;

static void mark_dead(struct thread *child, void *args_ UNUSED) {
  struct thread *cur = thread_current();

  if (child->parent_thread == cur) {
    child->parent_thread = NULL;
  }
}

static thread_action_func check_running_code_writable;

static void check_running_code_writable(struct thread *t, void *arg) {
  struct thread *cur = thread_current();
  if (strlen(t->running_code_filename) != 0 && strcmp(cur->running_code_filename, t->running_code_filename) && t != cur) {
    *((bool *) arg) = false;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  thread_foreach(&mark_dead, (void *) 0);
  struct thread *parent = cur->parent_thread;

  uint32_t *pd;

  bool can_allow_writes = true;

  int old = intr_disable();
  thread_foreach (&check_running_code_writable, &can_allow_writes);
  intr_set_level(old);

  if(can_allow_writes && cur->running_code_file != NULL) {
    file_allow_write(cur->running_code_file);
  }

  file_close(cur->running_code_file);

  if(parent != NULL) {
    lock_acquire(&(parent->waiting_child_lock));
    struct list_elem *e;
    for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
      struct child_thread_info *child = list_entry(e, struct child_thread_info, waiting_list_elem);
      if (child->tid == cur->tid) {
        child->dead = true;
        child->status = cur->exit_status;
        break;
      }
    }
    cond_signal(&(parent->waiting_for_child), &(parent->waiting_child_lock));
    lock_release(&(parent->waiting_child_lock));
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct arguments *args, void (**eip) (void), void **esp) 
{
	struct thread *t = thread_current ();
  // Our variables
  void *stack_pointers[args->num_args];
  char *top = (char *) PHYS_BASE;
  int extra_bytes;
  int zero = 0;


  
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (args->args[0]);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", args->args[0]);
      goto done; 
    }

  file_deny_write(file);
  t->running_code_file = file;
  strlcpy(t->running_code_filename, args->args[0], 20);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", args->args[0]);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  // Make the magic happen, put the parameters on the stack, storing
  // the addresses of these locations in stack_pointers
  for (i = args->num_args - 1; i >= 0; i--) {
    int total_length = strlen(args->args[i]) + 1;
    char *dest = top - total_length;
    memcpy((void *) dest, (void *) args->args[i], total_length);
    stack_pointers[i] = (void *) dest;
    top = dest;
  }

  // Add extra bytes for word alignment
  extra_bytes = (uint32_t) top % WORD_SIZE;
  for (i = 0; i < extra_bytes; i++) {
    memcpy(top - 1, &zero, 1);
    top--;
  }

  // Push a null word, and then the addresses of the other parameters
  memcpy(top - WORD_SIZE, &zero, WORD_SIZE);
  top -= WORD_SIZE;
  
  for (i = args->num_args - 1; i >= 0; i--) {
    memcpy(top - WORD_SIZE, &stack_pointers[i], WORD_SIZE);
    top -= WORD_SIZE;
  }
  
  // Push a pointer to the first address
  memcpy(top - WORD_SIZE, &top, WORD_SIZE);
  top -= WORD_SIZE;

  // Push the number of arguments
  memcpy(top - WORD_SIZE, &(args->num_args), WORD_SIZE);
  top -= WORD_SIZE;

  // Push a null return address
  memcpy(top - WORD_SIZE, &zero, WORD_SIZE);
  top -= WORD_SIZE;

  // Point the stack pointer
  *esp = (void *) top;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // We will close the file in process exit, so as to deny writes to executables
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);


  // printf("Read-bytes: %d\n", read_bytes);
  // printf("Zero-bytes: %d\n", zero_bytes);
  
  // return true;

  // file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // /* Get a page of memory. */
      // uint8_t *kpage = frame_alloc();
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     frame_free(kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);
      add_data_mapping(file, ofs, page_read_bytes, page_zero_bytes, writable, upage);
      ofs += page_read_bytes;

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //   {
      //     frame_free(kpage);
      //     return false; 
      //   }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_alloc();
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_free(kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

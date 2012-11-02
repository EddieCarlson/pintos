#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "threads/interrupt.h"


/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* tom: after you read what's below, you might wonder why Pintos 
 * allocates the thread
 * control block on the thread kernel stack.  One reason is to save
 * work -- but our goal isn't to build the fastest possible operating
 * system, so that's pretty lame.  Another reason is that "malloc"
 * uses locks and therefore the current thread, and so that means
 * you can't use malloc until the thread system is initalized, but if
 * the thread system needs to call malloc, ...
 *
 * This way, we can find the current thread from
 * the current stack pointer.  (On a uniprocessor, you
 * can stick the current thread in a static variable, but on a multiprocessor,
 * each processor has its own current thread -- but each processor
 * has its own stack pointer, so that works out!)
 *
 * OK, then, why does Pintos put the thread control block at the end
 * of the stack where it might be clobbered by a procedure call, rather
 * than underneath the stack where it will be safe?  I would have, but they
 * chose to do it this way in part because they want to reuse the stack
 * used in "main()" to become a thread stack, and the loader didn't
 * reserve enough room under the stack pointer for the thread control block.
 *
 * Similarly, rather than having a separate list of threads, the
 * list element data structure is embedded inside the thread control
 * block.  This is a bit of a pain for bookkeeping, but it has the upside
 * that you only need to allocate one block of data per thread.
 * This reduces error handling code, in case you might run out of memory --
 * you'll only get that error when you init the thread, not when it 
 * tries to wait.
 */
/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

/* Info struct for children processes */
struct child_thread_info {
  bool dead;
  tid_t tid;
  int status;
  struct list_elem waiting_list_elem;
};

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */
	
	  int sleep_start;					/* When thread started sleeping */
	  int sleep_total;					/* Length of time thread must sleep */
	
    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
	
	  struct list_elem sleeping_elem;		/* Sleeping list element */
    struct list_elem blocked_elem;    /* Blocked list element */

    struct lock *blocked_lock;    /* Lock that it may be blocked on */

    int original_priority;        /* The original priority given to the thread.
                                     For use in priority donation. */
	
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    uint32_t next_fd;
    struct list fd_list;

    struct thread *parent_thread;
    struct lock forking_child_lock;
    struct intr_frame i_f;
#endif

    // For managing child processes in wait and fork
    struct list child_list;
    struct condition waiting_for_child;
    struct lock waiting_child_lock;

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

struct list *get_sleeping_list(void);
struct list *get_blocked_list(void);

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

int get_max_ready_priority (void);

#endif /* threads/thread.h */

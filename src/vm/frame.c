#include "vm/frame.h"

#include "devices/block.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

#include <bitmap.h>
#include <list.h>
#include <stdbool.h>
#include <string.h>

struct frame {
  struct list_elem frame_elem;
  struct thread *user;

  void *base;
  void *vaddr;
  bool available;
  bool writable;
};

static struct list frame_list;
static struct list_elem *clock_pointer;
static struct lock ft_lock;

static struct frame *get_frame_by_paddr(void *paddr);

void frame_init() {
  list_init(&frame_list);
  //lock_init(&ft_lock);

  void *next_base = palloc_get_page(PAL_ZERO | PAL_USER);

  while (next_base != NULL) {

    struct frame *next_frame = (struct frame *) malloc(sizeof(struct frame));
    next_frame->base = next_base;
    next_frame->available = true;

    list_push_back(&frame_list, &(next_frame->frame_elem));

    next_base = palloc_get_page(PAL_ZERO | PAL_USER);
  }

  clock_pointer = list_begin(&frame_list);
}

void *frame_alloc() {
  // Lock this?
  // lock_acquire(&ft_lock);
  struct list_elem *e;

  void *found = NULL;

  for (e = list_begin(&frame_list); e != list_end (&frame_list); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, frame_elem);

    // Lock this!
    if (f->available) {
      f->available = false;

      found = f->base;
      break;
    }
  }

  if (found == NULL) {
    found = evict();
  }

  // lock_release(&ft_lock);
  return found;

  // Add candidate to swap partition (make sure to lock)

  // Remove from frame table

  // Give frame to process
  //PANIC ("frame_alloc: out of frames");
}

bool frame_free(void *frame_addr) {

  // lock_acquire(&ft_lock);
  struct list_elem *e;
  bool found = false;

  for (e = list_begin(&frame_list); e != list_end (&frame_list); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, frame_elem);

    // Lock this!
    if (f->base == frame_addr) {
      f->available = true;
      found = true;

      memset (f->base, 0, PGSIZE);

      // Remove from list of users!
      break;
    }
  }

  // lock_release(&ft_lock);
  return found;
}

void *evict(void) {
  // Assumes that the frame table has no available frames

  // Lock this!
  struct thread *cur = thread_current();
  struct frame *candidate = NULL;

  // Run clock to find suitable candidate
  while (true) {
    struct frame *f = list_entry(clock_pointer, struct frame, frame_elem);
    bool access_bit = pagedir_is_accessed (cur->pagedir, f->vaddr);
    if (!access_bit) {
      // Found one, increment the pointer and break
      if (clock_pointer == list_end(&frame_list)) {
        clock_pointer = list_begin(&frame_list);
      } else {
        clock_pointer = list_next(clock_pointer);
      }
      candidate = f;
      break;
    }

    pagedir_set_accessed (cur->pagedir, f->vaddr, false);
    if (clock_pointer == list_end(&frame_list)) {
      clock_pointer = list_begin(&frame_list);
    } else {
      clock_pointer = list_next(clock_pointer);
    }
  }

  ASSERT(candidate != NULL);

  // printf("Base: %p\n", candidate->base);
  // printf("Vaddr: %p\n", candidate->vaddr);

  // Evict suitable candidate
  block_sector_t swap_idx = swap_write_page(candidate->base);
  add_swap_mapping(swap_idx, candidate->user, candidate->vaddr, candidate->writable);

  // Update frame data (frame_install)
  pagedir_clear_page(candidate->user->pagedir, candidate->vaddr);
  candidate->user = cur;

  return candidate->base;

}

bool install_frame (void *upage, void *kpage, bool writable) {
  //lock_acquire(&ft_lock);
  struct thread *cur = thread_current ();

  struct frame *f = get_frame_by_paddr(kpage);
  bool success = (pagedir_get_page (cur->pagedir, upage) == NULL
          && pagedir_set_page (cur->pagedir, upage, kpage, writable));

  if (success) {
    f->user = cur;
    f->vaddr = upage;
    f->writable = writable;
  }

  //lock_release(&ft_lock);
  return success;
}

static struct frame *get_frame_by_paddr(void *paddr) {
  struct list_elem *e;

  for (e = list_begin(&frame_list); e != list_end (&frame_list); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, frame_elem);
    if (f->base == paddr) {
      return f;
    }
  }

  return NULL;
}

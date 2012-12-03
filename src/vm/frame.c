#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

#include "vm/frame.h"
#include <bitmap.h>
#include <list.h>
#include <stdbool.h>
#include <string.h>

struct frame {
  struct list_elem frame_elem;
  struct list users;

  void *base;
  bool available;
};

// struct user {

// }

static struct list frame_list;
static struct frame *clock_pointer;

void frame_init() {
  list_init(&frame_list);

  void *next_base = palloc_get_page(PAL_ZERO | PAL_USER);
  while (next_base != NULL) {

    struct frame *next_frame = (struct frame *) malloc(sizeof(struct frame));
    next_frame->base = next_base;
    next_frame->available = true;
    list_init(&(next_frame->users));

    list_push_back(&frame_list, &(next_frame->frame_elem));

    next_base = palloc_get_page(PAL_ZERO | PAL_USER);
  }

}

void *frame_alloc() {
  // Simple case: there are free frames (not in use)
  struct list_elem *e;

  for (e = list_begin(&frame_list); e != list_end (&frame_list); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, frame_elem);

    // Lock this!
    if (f->available) {
      f->available = false;

      // Add to list of users

      return f->base;
    }
  }
  
  PANIC ("frame_alloc: out of frames");
}

void frame_free(void *frame_addr) {

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
    }
  }

  if (!found) {
    PANIC("frame_free: you can't free that!");  
  }
  
}
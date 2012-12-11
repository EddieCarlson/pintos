#include "vm/page.h"
#include <hash.h>
#include <stdbool.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

unsigned std_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct spt_value *h = hash_entry(e, struct spt_value, spt_elem);
  return hash_bytes(&h->upage, sizeof(h->upage));
}

bool std_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct spt_value *one = hash_entry (a, struct spt_value, spt_elem);
  struct spt_value *two = hash_entry (b, struct spt_value, spt_elem);

  return one->upage < two->upage;
}

void add_data_mapping(struct file *f, off_t offs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, uint8_t *upage) {
  struct thread *cur = thread_current();
  struct spt_value *val = (struct spt_value *) malloc(sizeof(struct spt_value));
  val->is_data_code = true;
  val->upage = upage;

  val->f = f;
  val->offs = offs;
  val->read_bytes = read_bytes;
  val->zero_bytes = zero_bytes;
  val->writable = writable;

  hash_insert(&cur->spt, &val->spt_elem);
}

void add_file_memory_mapping(struct file *f, off_t offs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, void *addr, int map_id) {
  struct thread *cur = thread_current();
  add_data_mapping(f, offs, read_bytes, zero_bytes, writable, (uint8_t *) addr);
  
  // Add to thread's mmt
  struct mmt_value *val = (struct mmt_value *) malloc(sizeof(struct mmt_value));
  val->f = f;
  val->offs = offs;
  val->page_bytes = read_bytes;
  val->map_id = map_id;
  val->page_base = addr + offs;

  list_push_back(&cur->mmt, &val->mmt_elem);
}

void add_swap_mapping(block_sector_t swap_idx, struct thread *owner, void *uaddr, bool writable) {
  struct spt_value *val = (struct spt_value *) malloc(sizeof(struct spt_value));
  val->is_data_code = false;
  val->upage = uaddr;
  val->writable = writable;

  val->swap_idx = swap_idx;

  hash_insert(&owner->spt, &val->spt_elem);
}

void mmt_destroy(struct list *mmt) {
  while (!list_empty(mmt)) {
    struct list_elem *e = list_begin(mmt);
    struct mmt_value *val = list_entry(e, struct mmt_value, mmt_elem);
    mmt_unmap(mmt, val->map_id);
  }
}

void mmt_unmap(struct list *mmt, int map_id) {
  struct thread *cur = thread_current();
  struct list_elem *e = list_begin(mmt);
  struct file *f = NULL;

  while (e != list_end(mmt)) {
    struct mmt_value *val = list_entry(e, struct mmt_value, mmt_elem);

    bool update = true;
    if (val->map_id == map_id) {
      f = val->f;

      // Write back to the file if the page has been modified
      if (pagedir_is_dirty(cur->pagedir, val->page_base)) {
        file_write_at(f, val->page_base, val->page_bytes, val->offs);
      }

      update = false;
      e = list_next(e);
      list_remove(&val->mmt_elem);

      void *frame_addr = pagedir_get_page(cur->pagedir, val->page_base);
      if (frame_addr != NULL) {
        frame_free(frame_addr);  
      }
      
      free(val);
    }

    if (update) {
      e = list_next(e);
    }
  }

  file_close(f);
}

struct spt_value *get_by_vaddr(uint8_t *vaddr) {
  struct thread *cur = thread_current();
  struct spt_value p;
  struct hash_elem *e;

  p.upage = vaddr;
  e = hash_find (&cur->spt, &p.spt_elem);
  return e != NULL ? hash_entry (e, struct spt_value, spt_elem) : NULL;
}
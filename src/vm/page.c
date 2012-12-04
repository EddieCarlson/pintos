#include "vm/page.h"
#include <hash.h>
#include <stdbool.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

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

struct spt_value *get_by_vaddr(uint8_t *vaddr) {
  struct thread *cur = thread_current();
  struct spt_value p;
  struct hash_elem *e;

  p.upage = vaddr;
  e = hash_find (&cur->spt, &p.spt_elem);
  return e != NULL ? hash_entry (e, struct spt_value, spt_elem) : NULL;
}
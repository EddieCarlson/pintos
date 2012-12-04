#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include <inttypes.h>

#include "filesys/off_t.h"

hash_hash_func std_hash;
hash_less_func std_hash_less;


struct spt_value {
  struct hash_elem spt_elem;

  bool is_data_code;
  uint8_t *upage;

  // Data/Code metadata
  struct file *f;
  off_t offs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;

  // Swap metadata???

};

void add_data_mapping(struct file *f, off_t offs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, uint8_t *upage);

//void add_swap_mapping()

struct spt_value *get_by_vaddr(uint8_t *vaddr);

#endif
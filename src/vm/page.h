#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include <inttypes.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/thread.h"


hash_hash_func std_hash;
hash_less_func std_hash_less;

// hash_hash_func mmt_hash;
// hash_less_func mmt_hash_less;

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
  block_sector_t swap_idx;

};

struct mmt_value {
  struct list_elem mmt_elem;

  struct file *f;
  off_t offs;
  uint32_t page_bytes;
  int map_id;

  void *page_base;
};

void add_data_mapping(struct file *f, off_t offs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, uint8_t *upage);
void add_file_memory_mapping(struct file *f, off_t offs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, void *addr, int map_id);
void add_swap_mapping(block_sector_t swap_idx, struct thread *owner, void *uaddr, bool writable);
void mmt_destroy(struct list *mmt);
void mmt_unmap(struct list *mmt, int map_id);


//void add_swap_mapping()

struct spt_value *get_by_vaddr(uint8_t *vaddr);

#endif
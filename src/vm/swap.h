#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <list.h>
#include <stdbool.h>

#include "devices/block.h"

struct swap_page {
  block_sector_t start_sector;
  bool available;
};

void swap_init(void);
block_sector_t swap_write_page(void *frame_addr);
void swap_free(block_sector_t swap_idx);
void swap_read_page(block_sector_t swap_idx, void *frame_addr, bool free);

#endif
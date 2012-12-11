#include "vm/swap.h"

#include <stdbool.h>

#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

struct block *swap_block;
uint32_t num_swap_pages;
struct swap_page *swap_pages;

void swap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);
  num_swap_pages = block_size(swap_block) / 8;

  swap_pages = (struct swap_page *) malloc(sizeof(struct swap_page) * num_swap_pages);
  
  uint32_t i;
  for (i = 0; i < num_swap_pages; i++) {
    swap_pages[i].available = true;
    swap_pages[i].start_sector = i * 8;
  }
}

block_sector_t swap_write_page(void *frame_addr) {
  uint32_t i;
  for (i = 0; i < num_swap_pages; i++) {
    if (swap_pages[i].available) {
      swap_pages[i].available = false;

      if (swap_pages[i].start_sector == 8) {
        int p = 0;
      }  

      block_sector_t j;
      for (j = 0; j < 8; j++) {
        block_write(swap_block, swap_pages[i].start_sector + j,  frame_addr + j * 128);
      }

      return swap_pages[i].start_sector;
    }
  }

  PANIC("swap_write_page: Swap is full");
}

void swap_free(block_sector_t swap_idx) {
  uint32_t i;
  for (i = 0; i < num_swap_pages; i++) {
    if (swap_pages[i].start_sector == swap_idx) {
      swap_pages[i].available = true;
      return;
    }
  }
}

void swap_read_page(block_sector_t swap_idx, void *frame_addr, bool free) {
  uint32_t i;
  for (i = 0; i < num_swap_pages; i++) {
    if (swap_pages[i].start_sector == swap_idx) {

      block_sector_t j;
      for (j = 0; j < 8; j++) {
        block_read(swap_block, swap_pages[i].start_sector + j, frame_addr + j * 128);
      }

      if (free) {
        swap_pages[i].available = true;
      }
      return;
    }
  }
}


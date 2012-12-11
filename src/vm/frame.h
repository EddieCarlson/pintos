#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <stdbool.h>

void frame_init(void);
void *frame_alloc(void);
bool frame_free(void *);
bool install_frame (void *upage, void *kpage, bool writable);
void *evict(void);

#endif
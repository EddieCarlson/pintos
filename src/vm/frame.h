#ifndef VM_FRAME_H
#define VM_FRAME_H

void frame_init(void);
void *frame_alloc(void);
void frame_free(void *);

#endif
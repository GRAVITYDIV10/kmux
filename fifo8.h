#ifndef _FIFO8_H_
#define _FIFO8_H_

#include <stdint.h>
#include <assert.h>

typedef struct {
	uint8_t *data;
	unsigned int mask;
	unsigned int head;
	unsigned int num;
} fifo8;

static inline void fifo8_reset(fifo8 *fifo) {
	fifo->num = 0;
	fifo->head = 0;
}

static inline void fifo8_push(fifo8 *fifo, uint8_t datain) {
	assert(fifo->num <= fifo->mask);
	fifo->data[(fifo->head + fifo->num) & fifo->mask] = datain;
	fifo->num++;
}

static inline uint8_t fifo8_pop(fifo8 *fifo) {
    uint8_t ret;

    assert(fifo->num > 0);
    ret = fifo->data[fifo->head++];
    fifo->head &= fifo->mask;
    fifo->num--;
    return ret;
}

static inline unsigned int fifo8_num_free(fifo8 *fifo) {
	return (fifo->mask - fifo->num);
}

static inline unsigned int fifo8_num_used(fifo8 *fifo) {
	return fifo->num;
}

#endif

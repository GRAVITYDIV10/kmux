#ifndef _KERMIT_H_
#define _KERMIT_H_

#include <stdint.h>

#define kermit_tochar(x) ((x) + 32)
#define kermit_unchar(x) ((x) - 32)
#define kermit_ctl(x) ((x) ^ 64)
#define kermit_tosum(x) (kermit_tochar(((x) + (((x) >> 6) & 3)) & 0x3f))

//#define KERMIT_LINK_CTRL
//#define KERMIT_LINK_7BIT

#ifndef KERMIT_PKT_MAXSIZE
#define KERMIT_PKT_MAXSIZE 96
#endif

#ifndef KERMIT_MARK
#define KERMIT_MARK 0x01
#endif

#ifndef KERMIT_QCTL
#define KERMIT_QCTL '#'
#endif

#ifndef KERMIT_QBIN
#define KERMIT_QBIN '&'
#endif


enum {
	KERMIT_OFFSET_MARK = 0,
	KERMIT_MARK_SIZE = 1,

	KERMIT_OFFSET_LEN = 1,
	KERMIT_LEN_SIZE = 1,

	KERMIT_OFFSET_SEQ = 2,
	KERMIT_SEQ_MIN = 0,
	KERMIT_SEQ_MAX = 63,
	KERMIT_SEQ_MASK = 63,
	KERMIT_SEQ_SIZE = 1,

	KERMIT_OFFSET_TYPE = 3,
	KERMIT_TYPE_MIN = 32,
	KERMIT_TYPE_MAX = 126,
	KERMIT_TYPE_SIZE = 1,

	KERMIT_HDR_SIZE = KERMIT_MARK_SIZE + KERMIT_LEN_SIZE +
			KERMIT_SEQ_SIZE + KERMIT_TYPE_SIZE,

	KERMIT_OFFSET_DATA = 4,

	KERMIT_SUM_SIZE = 1,

	KERMIT_LEN_MIN = KERMIT_SEQ_SIZE + KERMIT_TYPE_SIZE + KERMIT_SUM_SIZE,
	KERMIT_LEN_MAX = KERMIT_PKT_MAXSIZE - KERMIT_MARK_SIZE - KERMIT_LEN_SIZE,

	KERMIT_QCTL_SIZE = 1,
	KERMIT_QBIN_SIZE = 1,

	KERMIT_ENC_MAXSIZE = KERMIT_QBIN_SIZE + KERMIT_QCTL_SIZE + 1,

};

enum {
	KERMIT_TYPE_ACK = 'Y',
	KERMIT_TYPE_NAK = 'N',
	KERMIT_TYPE_FHDR = 'F',
	KERMIT_TYPE_DATA = 'D',
	KERMIT_TYPE_EOF = 'Z',
	KERMIT_TYPE_BREAK = 'B',

	KERMIT_TYPE_ECHO = 'e',
	KERMIT_TYPE_TAP = 'p',
	KERMIT_TYPE_TUN = 'n',
};

typedef struct {
	uint8_t buf[KERMIT_PKT_MAXSIZE];
	int idx;
	int len;
} kermit_slot;

int kermit_is_control(uint8_t datain);

int kermit_pktlen_get(uint8_t *pkt);
uint8_t kermit_pktsum_get(uint8_t *pkt);
void kermit_pktsum_set(uint8_t *pkt, uint8_t newsum);
uint8_t kermit_pktsum_compute(uint8_t *pkt);
int kermit_pktsum_chk(uint8_t *pkt);
void kermit_pktsum_update(uint8_t *pkt);

void kermit_slot_reset(kermit_slot *kslot);
void kermit_slot_recv(kermit_slot *kslot, uint8_t datain);

int kermit_encode(uint8_t datain[1], uint8_t dataout[KERMIT_ENC_MAXSIZE]);
int kermit_decode(uint8_t datain[KERMIT_ENC_MAXSIZE], uint8_t dataout[1]);

int kermit_pkt_make(uint8_t *pktout, uint8_t type, uint8_t seq,
			uint8_t *datain, int inlen);

int kermit_pkt_decode_inplace(uint8_t *pktin);

#endif

#ifndef _KERMIT_H_
#define _KERMIT_H_

#include <stdint.h>

enum {
	KERMIT_MARK = 0x01,
	KERMIT_OFFSET_MARK = 0,
	KERMIT_MARK_SIZE = 1,
	KERMIT_OFFSET_BLEN = 1,
	KERMIT_BLEN_SIZE = 1,
	KERMIT_OFFSET_SEQ = 2,
	KERMIT_SEQ_SIZE = 1,
	KERMIT_OFFSET_TYPE = 3,
	KERMIT_TYPE_SIZE = 1,

	KERMIT_BHDR_SIZE = 4,

	KERMIT_OFFSET_LX1 = 4,
	KERMIT_LX1_SIZE = 1,
	KERMIT_OFFSET_LX2 = 5,
	KERMIT_LX2_SIZE = 1,
	KERMIT_OFFSET_HSUM = 6,
	KERMIT_HSUM_SIZE = 1,

	KERMIT_XHDR_SIZE = 7,

	KERMIT_SUM1_SIZE = 1,
	KERMIT_SUM2_SIZE = 2,
	KERMIT_SUM3_SIZE = 3,
	KERMIT_SUM_MAXSIZE = 3,

	KERMIT_TOCHAR_MAX = 94,
	KERMIT_TOCHAR_MIN = 0,

	KERMIT_BPKT_MINLEN = KERMIT_BHDR_SIZE + KERMIT_SUM1_SIZE,
	KERMIT_BPKT_MAXLEN = KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE + KERMIT_TOCHAR_MAX,
	KERMIT_XPKT_MINLEN = KERMIT_XHDR_SIZE + KERMIT_SUM1_SIZE,
	KERMIT_XPKT_MAXLEN = KERMIT_XHDR_SIZE + (KERMIT_TOCHAR_MAX * 95) + KERMIT_TOCHAR_MAX,

	KERMIT_SEQ_MIN = 0,
	KERMIT_SEQ_MAX = 63,
	KERMIT_SEQ_MASK = 63,

	KERMIT_PRINTABLE_MAX = 126,
	KERMIT_PRINTABLE_MIN = 32,

	KERMIT_TYPE_MAX = KERMIT_PRINTABLE_MAX,
	KERMIT_TYPE_MIN = KERMIT_PRINTABLE_MIN,

	KERMIT_LX1_MIN = 0,
	KERMIT_LX1_MAX = KERMIT_TOCHAR_MAX,

	KERMIT_LX2_MIN = 0,
	KERMIT_LX2_MAX = KERMIT_TOCHAR_MAX,

	KERMIT_PARAM_OFFSET_MAXBLEN = 0,
	KERMIT_PARAM_OFFSET_TIMO = 1,
	KERMIT_PARAM_OFFSET_NPAD = 2,
	KERMIT_PARAM_OFFSET_PADC = 3,
	KERMIT_PARAM_OFFSET_EOL  = 4,
	KERMIT_PARAM_OFFSET_QCTL = 5,
	KERMIT_BPARAM_SIZE = 6,
	KERMIT_PARAM_OFFSET_QBIN = 6,
	KERMIT_PARAM_OFFSET_CHKT = 7,
	KERMIT_PARAM_OFFSET_REPT = 8,
	KERMIT_PARAM_OFFSET_CAPAS = 9,
	KERMIT_PARAM_OFFSET_WINDO = 10,
	KERMIT_PARAM_OFFSET_MAXLX1 = 11,
	KERMIT_PARAM_OFFSET_MAXLX2 = 12,
	KERMIT_EPARAM_SIZE = 13,

	KERMIT_CAPAS_XLEN = (1 << 1),

	KERMIT_ENC_MINSIZE = 1,
	KERMIT_ENC_MAXSIZE = 3,

	KERMIT_TYPE_SINIT = 'S',
	KERMIT_TYPE_FHDR = 'F',
	KERMIT_TYPE_DATA = 'D',
	KERMIT_TYPE_ACK = 'Y',
	KERMIT_TYPE_NAK = 'N',
	KERMIT_TYPE_EOF = 'Z',
	KERMIT_TYPE_BREAK = 'B',
	KERMIT_TYPE_ERROR = 'E',
};

struct kermit_packet {
	int8_t *data;
	int16_t head;
	int16_t num;
	int16_t size;
};

struct kermit_context {
	struct kermit_packet *pktrx;
	struct kermit_packet *pkttx;
	int8_t *param;
	int8_t seqnum;
	int8_t state;
};

#define kermit_tochar(x) ((x) + 32)
#define kermit_unchar(x) ((x) - 32)
#define kermit_toctl(x) ((x) ^ 64)
#define kermit_tosum1(x) (kermit_tochar(((x) + (((x) >> 6) & 3)) & 0x3f))

int kermit_mark_get(int8_t *pkt);
void kermit_mark_set(int8_t *pkt, int8_t data);
int kermit_mark_chk(int8_t *pkt);

int kermit_blen_get(int8_t *pkt);
void kermit_blen_set(int8_t *pkt, int8_t len);
int kermit_blen_chk(int8_t *pkt);

int kermit_seq_get(int8_t *pkt);
void kermit_seq_set(int8_t *pkt, int8_t seq);
int kermit_seq_chk(int8_t *pkt);

int kermit_type_get(int8_t *pkt);
void kermit_type_set(int8_t *pkt, int8_t type);
int kermit_type_chk(int8_t *pkt);

int kermit_lx1_get(int8_t *pkt);
void kermit_lx1_set(int8_t *pkt, int8_t lx1);
int kermit_lx1_chk(int8_t *pkt);

int kermit_lx2_get(int8_t *pkt);
void kermit_lx2_set(int8_t *pkt, int8_t lx2);
int kermit_lx2_chk(int8_t *pkt);

int16_t kermit_xlen_get(int8_t *pkt);
void kermit_xlen_set(int8_t *pkt, int16_t len);
int kermit_xlen_chk(int8_t *pkt);

int kermit_is_bpkt(int8_t *pkt);
int kermit_is_xpkt(int8_t *pkt);

int16_t kermit_len_get(int8_t *pkt);

int kermit_sum1_compute(int8_t *buf, int16_t len);

int kermit_hsum_get(int8_t *pkt);
void kermit_hsum_set(int8_t *pkt, int hsum);
int kermit_hsum_compute(int8_t *pkt);
int kermit_hsum_chk(int8_t *pkt);

int kermit_maxblen_get(int8_t *param);
void kermit_maxblen_set(int8_t *param, int blen);
int kermit_maxblen_chk(int8_t *param);

int kermit_qctl_get(int8_t *param);
void kermit_qctl_set(int8_t *param, int qctl);
int kermit_qctl_chk(int8_t *param);

int kermit_qbin_get(int8_t *param);
void kermit_qbin_set(int8_t *param, int qbin);
int kermit_qbin_chk(int8_t *param);

int kermit_qctl_valid(int8_t *param);
int kermit_qbin_valid(int8_t *param);

int kermit_chkt_get(int8_t *param);
void kermit_chkt_set(int8_t *param, int chkt);
int kermit_chkt_chk(int8_t *param);

int kermit_rept_get(int8_t *param);
void kermit_rept_set(int8_t *param, int rept);
int kermit_rept_chk(int8_t *param);

int kermit_rept_valid(int8_t *param);

int kermit_capas_get(int8_t *param);
void kermit_capas_set(int8_t *param, int rept);
int kermit_capas_chk(int8_t *param);

int kermit_xlen_valid(int8_t *param);

int kermit_maxlx1_get(int8_t *param);
void kermit_maxlx1_set(int8_t *param, int maxlx1);
int kermit_maxlx1_chk(int8_t *param);

int kermit_maxlx2_get(int8_t *param);
void kermit_maxlx2_set(int8_t *param, int maxlx2);
int kermit_maxlx2_chk(int8_t *param);

int16_t kermit_maxlx_get(int8_t *param);
void kermit_maxlx_set(int8_t *param, int16_t maxlx);
int kermit_maxlx_chk(int8_t *param);

int kermit_len_chk(int8_t *pkt, int8_t *param);

void kermit_len_plus(int8_t *pkt, int16_t n);

int16_t kermit_len_ava_get(int8_t *pkt, int8_t *param);

int kermit_chkt_len_get(int8_t *param);

int16_t kermit_data_ava_get(int8_t *pkt, int8_t *param);

int kermit_is_control(int8_t c);

int kermit_data_encode(int8_t *param, int8_t data, int8_t out[KERMIT_ENC_MAXSIZE]);
int kermit_data_decode(int8_t *param, int8_t in[KERMIT_ENC_MAXSIZE], int8_t *data);

int16_t kermit_data_offset_get(int8_t *pkt);

int kermit_sum_compute(int8_t *pkt, int8_t *param, int8_t out[KERMIT_SUM_MAXSIZE]);

int16_t kermit_sum_offset_get(int8_t *pkt, int8_t *param);

int kermit_sum_get(int8_t *pkt, int8_t *param, int8_t sum[KERMIT_SUM_MAXSIZE]);
void kermit_sum_set(int8_t *pkt, int8_t *param, int8_t sum[KERMIT_SUM_MAXSIZE]);
int kermit_sum_chk(int8_t *pkt, int8_t *param);

int16_t kermit_bpkt_make(int8_t *pkt, int8_t *param,
				int8_t seq, int8_t type,
				int8_t *in, int16_t inlen);

int16_t kermit_xpkt_make(int8_t *pkt, int8_t *param,
				int8_t seq, int8_t type,
				int8_t *in, int16_t inlen);

#endif

#include "kermit.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>

int kermit_mark_get(int8_t *pkt) {
	return pkt[KERMIT_OFFSET_MARK];
}

void kermit_mark_set(int8_t *pkt, int8_t data) {
	pkt[KERMIT_OFFSET_MARK] = data;
}

int kermit_mark_chk(int8_t *pkt) {
	return (kermit_mark_get(pkt) == KERMIT_MARK);
}

int kermit_blen_get(int8_t *pkt) {
	return (KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE +
		kermit_unchar(pkt[KERMIT_OFFSET_BLEN]));
}

void kermit_blen_set(int8_t *pkt, int8_t len) {
	len -= KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE;
	pkt[KERMIT_OFFSET_BLEN] = kermit_tochar(len);
}

int kermit_blen_chk(int8_t *pkt) {
	int blen;
	blen = kermit_blen_get(pkt);
	return ((blen >= KERMIT_BPKT_MINLEN) &&
		(blen <= KERMIT_BPKT_MAXLEN));
}

int kermit_seq_get(int8_t *pkt) {
	return kermit_unchar(pkt[KERMIT_OFFSET_SEQ]);
}

void kermit_seq_set(int8_t *pkt, int8_t seq) {
	pkt[KERMIT_OFFSET_SEQ] = kermit_tochar(seq & KERMIT_SEQ_MASK);
}

int kermit_seq_chk(int8_t *pkt) {
	int seq;
	seq = kermit_seq_get(pkt);
	return ((seq >= KERMIT_SEQ_MIN) &&
		(seq <= KERMIT_SEQ_MAX));
}

int kermit_type_get(int8_t *pkt) {
	return pkt[KERMIT_OFFSET_TYPE];
}

void kermit_type_set(int8_t *pkt, int8_t type) {
	pkt[KERMIT_OFFSET_TYPE] = type;
}

int kermit_type_chk(int8_t *pkt) {
	int type;
	type = kermit_type_get(pkt);
	return ((type >= KERMIT_TYPE_MIN) &&
		(type <= KERMIT_TYPE_MAX));
}

int kermit_lx1_get(int8_t *pkt) {
	return kermit_unchar(pkt[KERMIT_OFFSET_LX1]);
}

void kermit_lx1_set(int8_t *pkt, int8_t lx1) {
	pkt[KERMIT_OFFSET_LX1] = kermit_tochar(lx1);
}

int kermit_lx1_chk(int8_t *pkt) {
	int lx1;
	lx1 = kermit_lx1_get(pkt);
	return ((lx1 >= KERMIT_LX1_MIN) &&
		(lx1 <= KERMIT_LX1_MAX));
}

int kermit_lx2_get(int8_t *pkt) {
	return kermit_unchar(pkt[KERMIT_OFFSET_LX2]);
}

void kermit_lx2_set(int8_t *pkt, int8_t lx2) {
	pkt[KERMIT_OFFSET_LX2] = kermit_tochar(lx2);
}

int kermit_lx2_chk(int8_t *pkt) {
	int lx2;
	lx2 = kermit_lx2_get(pkt);
	return ((lx2 >= KERMIT_LX2_MIN) &&
		(lx2 <= KERMIT_LX2_MAX));
}

int16_t kermit_xlen_get(int8_t *pkt) {
	int len;
	len = kermit_lx1_get(pkt) * 95;
	len += kermit_lx2_get(pkt);
	return len + KERMIT_XHDR_SIZE;
}

void kermit_xlen_set(int8_t *pkt, int16_t len) {
	len -= KERMIT_XHDR_SIZE;
	kermit_lx1_set(pkt, len / 95);
	kermit_lx2_set(pkt, len % 95);
}

int kermit_xlen_chk(int8_t *pkt) {
	int len;
	len = kermit_xlen_get(pkt);
	return ((len >= KERMIT_XPKT_MINLEN) &&
		(len <= KERMIT_XPKT_MAXLEN));
}

int kermit_is_bpkt(int8_t *pkt) {
	if (pkt[KERMIT_OFFSET_BLEN] == 32) {
		return 0;
	}
	return 1;
}

int kermit_is_xpkt(int8_t *pkt) {
	return !kermit_is_bpkt(pkt);
}

int16_t kermit_len_get(int8_t *pkt) {
	if (kermit_is_bpkt(pkt)) {
		return kermit_blen_get(pkt);
	}
	return kermit_xlen_get(pkt);
}

int kermit_sum1_compute(int8_t *buf, int16_t len) {
	int16_t i;
	int sum = 0;
	for (i = 0; i < len; i++) {
		sum += buf[i];
	}
	return kermit_tosum1(sum);
}

int kermit_hsum_get(int8_t *pkt) {
	return pkt[KERMIT_OFFSET_HSUM];
}

void kermit_hsum_set(int8_t *pkt, int hsum) {
	pkt[KERMIT_OFFSET_HSUM] = hsum;
}

int kermit_hsum_compute(int8_t *pkt) {
	return kermit_sum1_compute(pkt + KERMIT_OFFSET_BLEN,
			KERMIT_XHDR_SIZE - KERMIT_MARK_SIZE - KERMIT_HSUM_SIZE);
}

int kermit_hsum_chk(int8_t *pkt) {
	int lhsum, rhsum;
	rhsum = kermit_hsum_get(pkt);
	lhsum = kermit_hsum_compute(pkt);
	return (rhsum == lhsum);
}

int kermit_maxblen_get(int8_t *param) {
	return (kermit_unchar(param[KERMIT_PARAM_OFFSET_MAXBLEN]) + 
			KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
}

void kermit_maxblen_set(int8_t *param, int blen) {
	blen -= KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE;
	param[KERMIT_PARAM_OFFSET_MAXBLEN] = kermit_tochar(blen);
}

int kermit_maxblen_chk(int8_t *param) {
	int maxblen;
	maxblen = kermit_maxblen_get(param);
	return ((maxblen >= KERMIT_BPKT_MINLEN) &&
		(maxblen <= KERMIT_BPKT_MAXLEN));
}

int kermit_qctl_get(int8_t *param) {
	return param[KERMIT_PARAM_OFFSET_QCTL];
}

void kermit_qctl_set(int8_t *param, int qctl) {
	param[KERMIT_PARAM_OFFSET_QCTL] = qctl;
}

int kermit_qctl_chk(int8_t *param) {
	int qctl;
	qctl = kermit_qctl_get(param);
	if ((qctl >= 32) && (qctl <= 62)) {
		return 1;
	}
	if ((qctl >= 96) && (qctl <= 126)) {
		return 1;
	}
	return 0;
}

int kermit_qbin_get(int8_t *param) {
	int qbin;
	qbin = param[KERMIT_PARAM_OFFSET_QBIN];
	if (qbin == 'Y') {
		qbin = '&';
	}
	return qbin;
}

void kermit_qbin_set(int8_t *param, int qbin) {
	param[KERMIT_PARAM_OFFSET_QBIN] = qbin;
}

int kermit_qbin_chk(int8_t *param) {
	int qbin;
	qbin = kermit_qbin_get(param);
	if ((qbin >= 32) && (qbin <= 62)) {
		return 1;
	}
	if ((qbin >= 96) && (qbin <= 126)) {
		return 1;
	}
	return 0;
}

int kermit_qctl_valid(int8_t *param) {
	int qctl, qbin;
	qctl = kermit_qctl_get(param);
	qbin = kermit_qbin_get(param);
	if (qctl == qbin) {
		return 0;
	}
	if (qctl == ' ') {
		return 0;
	}
	return kermit_qctl_chk(param);
}

int kermit_qbin_valid(int8_t *param) {
	int qctl, qbin;
	qctl = kermit_qctl_get(param);
	qbin = kermit_qbin_get(param);
	if (qctl == qbin) {
		return 0;
	}
	if (qbin == ' ') {
		return 0;
	}
	return kermit_qbin_chk(param);
}

int kermit_chkt_get(int8_t *param) {
	return param[KERMIT_PARAM_OFFSET_CHKT];
}

void kermit_chkt_set(int8_t *param, int chkt) {
	param[KERMIT_PARAM_OFFSET_CHKT] = chkt;
}

int kermit_chkt_chk(int8_t *param) {
	switch(kermit_chkt_get(param)) {
	case '1': case '2':
	case '3': case '5':
		return 1;
	}
	return 0;
}

int kermit_rept_get(int8_t *param) {
	return param[KERMIT_PARAM_OFFSET_REPT];
}

void kermit_rept_set(int8_t *param, int rept) {
	param[KERMIT_PARAM_OFFSET_REPT] = rept;
}

// this version not support rept
int kermit_rept_chk(int8_t *param) {
	if (kermit_rept_get(param) == ' ') {
		return 1; 
	}
	return 0;
}

int kermit_rept_valid(int8_t *param) {
	(void)param;
	return 0;
}

int kermit_capas_get(int8_t *param) {
	return kermit_unchar(param[KERMIT_PARAM_OFFSET_CAPAS]);
}

void kermit_capas_set(int8_t *param, int capas) {
	param[KERMIT_PARAM_OFFSET_CAPAS] = kermit_tochar(capas);
}

int kermit_capas_chk(int8_t *param) {
	int capas;
	capas = kermit_capas_get(param);
	if ((capas & ~(KERMIT_CAPAS_XLEN)) != 0) {
		return 0;
	}
	return 1;
}

int kermit_xlen_valid(int8_t *param) {
	int capas;
	capas = kermit_capas_get(param);
	return !!(capas & KERMIT_CAPAS_XLEN);
}

int kermit_maxlx1_get(int8_t *param) {
	return kermit_unchar(param[KERMIT_PARAM_OFFSET_MAXLX1]);
}

void kermit_maxlx1_set(int8_t *param, int maxlx1) {
	param[KERMIT_PARAM_OFFSET_MAXLX1] = kermit_tochar(maxlx1);
}
int kermit_maxlx1_chk(int8_t *param) {
	int maxlx1;
	maxlx1 = kermit_maxlx1_get(param);
	return ((maxlx1 >= KERMIT_LX1_MIN) &&
		(maxlx1 <= KERMIT_LX1_MAX));
}

int kermit_maxlx2_get(int8_t *param) {
	return kermit_unchar(param[KERMIT_PARAM_OFFSET_MAXLX2]);
}

void kermit_maxlx2_set(int8_t *param, int maxlx2) {
	param[KERMIT_PARAM_OFFSET_MAXLX2] = kermit_tochar(maxlx2);
}

int kermit_maxlx2_chk(int8_t *param) {
	int maxlx2;
	maxlx2 = kermit_maxlx2_get(param);
	return ((maxlx2 >= KERMIT_LX2_MIN) &&
		(maxlx2 <= KERMIT_LX2_MAX));
}

int16_t kermit_maxlx_get(int8_t *param) {
	int16_t maxlx;
	maxlx = kermit_maxlx1_get(param) * 95;
	maxlx += kermit_maxlx2_get(param);
	maxlx += KERMIT_XHDR_SIZE;
	return maxlx;
}

void kermit_maxlx_set(int8_t *param, int16_t maxlx) {
	maxlx -= KERMIT_XHDR_SIZE;
	kermit_maxlx1_set(param, maxlx / 95);
	kermit_maxlx2_set(param, maxlx % 95);
}

int kermit_maxlx_chk(int8_t *param) {
	int maxlx;
	maxlx = kermit_maxlx_get(param);
	return ((maxlx >= KERMIT_XPKT_MINLEN) &&
		(maxlx <= KERMIT_XPKT_MAXLEN));
}

int kermit_len_chk(int8_t *pkt, int8_t *param) {
	if ((kermit_xlen_valid(param) != 0) && (kermit_is_xpkt(pkt) != 0)) {
		int16_t xlen;
		xlen = kermit_xlen_get(pkt);
		return ((xlen >= KERMIT_XPKT_MINLEN) &&
			(xlen <= kermit_maxlx_get(param)));
	}
	int blen;
	blen = kermit_blen_get(pkt);
	return ((blen >= KERMIT_BPKT_MINLEN) &&
		(blen <= kermit_maxblen_get(param)));
}

void kermit_len_plus(int8_t *pkt, int16_t n) {
	if (kermit_is_xpkt(pkt) != 0) {
		int16_t xlen;
		xlen = kermit_xlen_get(pkt);
		xlen += n;
		kermit_xlen_set(pkt, xlen);
		return;
	}
	int blen;
	blen = kermit_blen_get(pkt);
	blen += n;
	kermit_blen_set(pkt, blen);
}

int16_t kermit_len_ava_get(int8_t *pkt, int8_t *param) {
	int16_t pktlen, maxlen;
	if (kermit_is_bpkt(pkt)) {
		pktlen = kermit_blen_get(pkt);
		maxlen = kermit_maxblen_get(param);
		return maxlen - pktlen;
	}
	pktlen = kermit_xlen_get(pkt);
	maxlen = kermit_maxlx_get(param);
	return maxlen - pktlen;
}

int kermit_chkt_len_get(int8_t *param) {
	int chkt;
	chkt = kermit_chkt_get(param);
	switch (chkt) {
	case '5': case '3':
		return 3;
	case '2':
		return 2;
	case '1':
	default:
		return 1;
	}
}

int16_t kermit_data_ava_get(int8_t *pkt, int8_t *param) {
	int16_t len_ava;
	len_ava = kermit_len_ava_get(pkt, param);
	return len_ava - kermit_chkt_len_get(param);
}

int kermit_is_control(int8_t c) {
	c &= ~(1 << 7);
	if (c == 127) { return 1; }
	if (c < 32) { return 1; }
	return 0;
}

int kermit_data_encode(int8_t *param, int8_t data, int8_t out[KERMIT_ENC_MAXSIZE]) {
	int qctl = 0;
	int qbin = 0;
	if (kermit_qctl_valid(param) != 0) { qctl = kermit_qctl_get(param); }
	if (kermit_qbin_valid(param) != 0) { qbin = kermit_qbin_get(param); }
	int idx = 0;
	if (qbin && (data & (1 << 7))) {
		data ^= (1 << 7);
		out[idx] = qbin; idx++;
	}
	if (qctl && (data == qctl)) {
		out[idx] = qctl; idx++;
		out[idx] = qctl; idx++;
		return idx;
	}
	if (qctl && qbin && (data == qbin)) {
		out[idx] = qctl; idx++;
		out[idx] = qbin; idx++;
		return idx;
	}
	if (qctl && kermit_is_control(data)) {
		out[idx] = qctl; idx++;
		out[idx] = kermit_toctl(data); idx++;
		return idx;
	}
	out[idx] = data; idx++;
	return idx;
}

int kermit_data_decode(int8_t *param, int8_t in[KERMIT_ENC_MAXSIZE], int8_t *data) {
	int qctl = 0;
	int qbin = 0;
	if (kermit_qctl_valid(param) != 0) { qctl = kermit_qctl_get(param); }
	if (kermit_qbin_valid(param) != 0) { qbin = kermit_qbin_get(param); }
	if (qctl && qbin && (in[0] == qbin) && (in[1] == qctl) &&
		((in[2] == qbin) || (in[2] == qctl))) {
		*data = in[2] ^ (1 << 7);
		return 3;
	}
	if (qctl && qbin && (in[0] == qbin) && (in[1] == qctl)) {
		*data = kermit_toctl(in[2]) ^ (1 << 7);
		return 3;
	}
	if (qctl && (in[0] == qctl) && (in[1] == qctl)) {
		*data = in[1];
		return 2;
	}
	if (qctl && qbin && (in[0] == qctl) && (in[1] == qbin)) {
		*data = in[1];
		return 2;
	}
	if (qctl && (in[0] == qctl)) {
		*data = kermit_toctl(in[1]);
		return 2;
	}
	if (qbin && (in[0] == qbin)) {
		*data = in[1] ^ (1 << 7);
		return 2;
	}
	*data = in[0];
	return 1;
}

int16_t kermit_data_offset_get(int8_t *pkt) {
	if (kermit_is_bpkt(pkt)) {
		return KERMIT_BHDR_SIZE;
	}
	return KERMIT_XHDR_SIZE;
}

int kermit_sum_compute(int8_t *pkt, int8_t *param, int8_t out[KERMIT_SUM_MAXSIZE]) {
	int chkt;
	chkt = kermit_chkt_get(param);
	int16_t len;
	len = kermit_len_get(pkt);
	switch(chkt) {
	case '5':
	case '3':
	case '2':
		return 0;
	default:
	case '1':
		out[0] = kermit_sum1_compute(&pkt[KERMIT_OFFSET_BLEN],
				len - KERMIT_MARK_SIZE - KERMIT_SUM1_SIZE);
		return 1;
	}
}

int16_t kermit_sum_offset_get(int8_t *pkt, int8_t *param) {
	int chkt_len;
	chkt_len = kermit_chkt_len_get(param);
	return kermit_len_get(pkt) - chkt_len;
}

int kermit_sum_get(int8_t *pkt, int8_t *param, int8_t sum[KERMIT_SUM_MAXSIZE]) {
	int chkt;
	chkt = kermit_chkt_get(param);
	int16_t sum_offset;
	sum_offset = kermit_sum_offset_get(pkt, param);
	switch(chkt) {
	case '5':
	case '3':
	case '2':
		return 0;
	default:
	case '1':
		sum[0] = pkt[sum_offset];
		return 1;
	}
}


void kermit_sum_set(int8_t *pkt, int8_t *param, int8_t sum[KERMIT_SUM_MAXSIZE]) {
	int chkt;
	chkt = kermit_chkt_get(param);
	int16_t sum_offset;
	sum_offset = kermit_sum_offset_get(pkt, param);
	switch(chkt) {
	case '5':
	case '3':
	case '2':
		return;
	default:
	case '1':
		pkt[sum_offset] = sum[0];
		return;
	}
}

int kermit_sum_chk(int8_t *pkt, int8_t *param) {
	int8_t sum_local[KERMIT_SUM_MAXSIZE];
	int8_t sum_remote[KERMIT_SUM_MAXSIZE];
	int ret;
	ret = kermit_sum_get(pkt, param, sum_remote);
	kermit_sum_compute(pkt, param, sum_local);
	return (memcmp(sum_remote, sum_local, ret) == 0);
}

int16_t kermit_bpkt_make(int8_t *pkt, int8_t *param,
				int8_t seq, int8_t type,
				int8_t *in, int16_t inlen) {
	kermit_mark_set(pkt, KERMIT_MARK);
	kermit_blen_set(pkt, KERMIT_BHDR_SIZE);
	kermit_seq_set(pkt, seq);
	kermit_type_set(pkt, type);

	int16_t used_len = 0;
	int16_t data_ava;
	data_ava = kermit_data_ava_get(pkt, param);
	int16_t outidx;
	outidx = kermit_data_offset_get(pkt);
	int16_t inidx;


	int enclen;
	int8_t encbuf[KERMIT_ENC_MAXSIZE];

	switch(type) {
	case KERMIT_TYPE_SINIT:
		used_len = MIN(data_ava, inlen);
		memcpy(&pkt[outidx], in, used_len);
		kermit_len_plus(pkt, used_len);
		break;
	default:
		for (inidx = 0; inidx < inlen; inidx++) {
			enclen = kermit_data_encode(param, in[inidx], encbuf);
			data_ava = kermit_data_ava_get(pkt, param);
			if (enclen > data_ava) {
				break;
			}
			memcpy(&pkt[outidx], encbuf, enclen);
			kermit_len_plus(pkt, enclen);
			outidx += enclen;
		}
		break;
	}
	int sum_size;
	sum_size = kermit_chkt_len_get(param);
	kermit_len_plus(pkt, sum_size);
	int8_t sum[KERMIT_SUM_MAXSIZE];
	kermit_sum_compute(pkt, param, sum);
	memcpy(&pkt[kermit_sum_offset_get(pkt, param)], sum, sum_size);

	return used_len;
}

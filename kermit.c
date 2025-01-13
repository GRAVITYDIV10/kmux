#include "kermit.h"

int kermit_is_control(uint8_t datain) {
	datain &= ~(1 << 7);
	return ((datain < 32) || (datain == 127));
}

int kermit_pktlen_get(uint8_t *pkt) {
	int pktlen;
	pktlen = (KERMIT_MARK_SIZE + KERMIT_LEN_SIZE +
		kermit_unchar(pkt[KERMIT_OFFSET_LEN]));
	if ((pktlen < 0) || (pktlen > KERMIT_PKT_MAXSIZE)) {
		return 0;
	}
	return pktlen;
}

uint8_t kermit_pktsum_get(uint8_t *pkt) {
	return pkt[kermit_pktlen_get(pkt) - KERMIT_SUM_SIZE];
}

void kermit_pktsum_set(uint8_t *pkt, uint8_t newsum) {
	pkt[kermit_pktlen_get(pkt) - KERMIT_SUM_SIZE] = newsum;
}

uint8_t kermit_pktsum_compute(uint8_t *pkt) {
	int i;
	int sum = 0;
	for (i = KERMIT_OFFSET_LEN;
		i < kermit_pktlen_get(pkt) - KERMIT_SUM_SIZE; i++) {
		sum += pkt[i];
	}
	return kermit_tosum(sum);
}

int kermit_pktsum_chk(uint8_t *pkt) {
	return (kermit_pktsum_get(pkt) == kermit_pktsum_compute(pkt));
}

void kermit_pktsum_update(uint8_t *pkt) {
	kermit_pktsum_set(pkt, kermit_pktsum_compute(pkt));
}

void kermit_slot_reset(kermit_slot *kslot) {
	kslot->idx = 0;
	kslot->len = 0;
}

void kermit_slot_recv(kermit_slot *kslot, uint8_t datain) {
	if (kslot->len != 0) { return; };
	if ((kslot->idx >= KERMIT_PKT_MAXSIZE) || (kslot->idx < 0)) {
		kermit_slot_reset(kslot);
		return;
	}
#ifdef KERMIT_LINK_7BIT
	datain &= ~(1 << 7);
#endif
	switch(kslot->idx) {
	case KERMIT_OFFSET_MARK:
		if (datain != KERMIT_MARK) {
			//kermit_slot_reset(kslot);
			return;
		}
		kslot->buf[kslot->idx] = datain;
		kslot->idx += 1;
		return;
	case KERMIT_OFFSET_LEN:
		if ((datain < kermit_tochar(KERMIT_LEN_MIN)) ||
			(datain > kermit_tochar(KERMIT_LEN_MAX))) {
			kermit_slot_reset(kslot);
			return;
		}
		kslot->buf[kslot->idx] = datain;
		kslot->idx += 1;
		return;
	case KERMIT_OFFSET_SEQ:
		if ((datain < kermit_tochar(KERMIT_SEQ_MIN)) ||
			(datain > kermit_tochar(KERMIT_SEQ_MAX))) {
			kermit_slot_reset(kslot);
			return;
		}
		kslot->buf[kslot->idx] = datain;
		kslot->idx += 1;
		return;
	case KERMIT_OFFSET_TYPE:
		if ((datain < KERMIT_TYPE_MIN) || (datain > KERMIT_TYPE_MAX)) {
			kermit_slot_reset(kslot);
			return;
		}
		kslot->buf[kslot->idx] = datain;
		kslot->idx += 1;
		return;
	}
#ifdef KERMIT_LINK_CTRL
	if (kermit_is_control(datain)) {
		kermit_slot_reset(kslot);
		return;
	}
#endif
	kslot->buf[kslot->idx] = datain;
	kslot->idx += 1;
	int pktlen;
	pktlen = kermit_pktlen_get(kslot->buf);
	if (kslot->idx >= pktlen) {
		kslot->len = kslot->idx;
		kslot->idx = 0;
		return;
	}
}

int kermit_encode(uint8_t datain[1], uint8_t dataout[KERMIT_ENC_MAXSIZE]) {
	int outlen = 0;
	uint8_t data;
	data = datain[0];
#ifdef KERMIT_LINK_7BIT
	if (data & (1 << 7)) {
		dataout[outlen] = KERMIT_QBIN; outlen++;
		data ^= (1 << 7);
	}
	if (data == KERMIT_QBIN) {
		dataout[outlen] = KERMIT_QCTL; outlen++;
		dataout[outlen] = KERMIT_QBIN; outlen++;
		return outlen;
	}
#endif
	if (data == KERMIT_QCTL) {
		dataout[outlen] = KERMIT_QCTL; outlen++;
		dataout[outlen] = KERMIT_QCTL; outlen++;
		return outlen;
	}
	if (data == KERMIT_MARK) {
		dataout[outlen] = KERMIT_QCTL; outlen++;
		dataout[outlen] = kermit_ctl(KERMIT_MARK); outlen++;
		return outlen;
	}
#ifdef KERMIT_LINK_CTRL
	if (kermit_is_control(data)) {
		dataout[outlen] = KERMIT_QCTL; outlen++;
		dataout[outlen] = kermit_ctl(data); outlen++;
		return outlen;
	}
#endif
	dataout[outlen] = data; outlen++;
	return outlen;
}

int kermit_decode(uint8_t datain[KERMIT_ENC_MAXSIZE], uint8_t dataout[1]) {
#ifdef KERMIT_LINK_7BIT
	if ((datain[0] == KERMIT_QBIN) && (datain[1] == KERMIT_QCTL) &&
		((datain[2] == KERMIT_QCTL) || (datain[2] == KERMIT_QBIN))) {
		dataout[0] = datain[2] | (1 << 7);
		return 3;
	}
	if ((datain[0] == KERMIT_QBIN) && (datain[1] == KERMIT_QCTL)) {
		dataout[0] = kermit_ctl(datain[2]) | (1 << 7);
		return 3;
	}
	if ((datain[0] == KERMIT_QCTL) && (datain[1] == KERMIT_QBIN)) {
		dataout[0] = KERMIT_QBIN;
		return 2;
	}
	if (datain[0] == KERMIT_QBIN) {
		dataout[0] = datain[1] | (1 << 7);
		return 2;
	}
#endif
	if ((datain[0] == KERMIT_QCTL) && (datain[1] == KERMIT_QCTL)) {
		dataout[0] = KERMIT_QCTL;
		return 2;
	}
	if (datain[0] == KERMIT_QCTL) {
		dataout[0] = kermit_ctl(datain[1]);
		return 2;
	}
	dataout[0] = datain[0];
	return 1;
}

int kermit_pkt_make(uint8_t *pktout, uint8_t type, uint8_t seq,
			uint8_t *datain, int inlen) {
	pktout[KERMIT_OFFSET_MARK] = KERMIT_MARK;
	pktout[KERMIT_OFFSET_LEN] = kermit_tochar(KERMIT_SEQ_SIZE +
					KERMIT_TYPE_SIZE + KERMIT_SUM_SIZE);
	pktout[KERMIT_OFFSET_SEQ] = kermit_tochar(seq & KERMIT_SEQ_MASK);
	pktout[KERMIT_OFFSET_TYPE] = type;

	int inidx = 0;
	int pktidx = KERMIT_OFFSET_DATA;
	int ret;
	while ((pktidx < (KERMIT_PKT_MAXSIZE - KERMIT_ENC_MAXSIZE)) &&
			(inidx < inlen)) {
		ret = kermit_encode(&datain[inidx], &pktout[pktidx]);
		inidx += 1;
		pktidx += ret;
		pktout[KERMIT_OFFSET_LEN] += ret;
	}
	kermit_pktsum_update(pktout);
	return inidx;
}

int kermit_pkt_decode_inplace(uint8_t *pktin) {
	int pktlen;
	pktlen = kermit_pktlen_get(pktin);
	int inidx;
	int outidx;
	inidx = KERMIT_OFFSET_DATA;
	outidx = inidx;

	int ret;
	while((inidx < (pktlen - KERMIT_SUM_SIZE)) &&
		(outidx <= inidx)) {
		ret = kermit_decode(&pktin[inidx], &pktin[outidx]);
		inidx += ret;
		outidx += 1;
	}
	return (outidx - KERMIT_HDR_SIZE);
}

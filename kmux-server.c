#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include "fifo8.h"
#include "kermit.h"

#define KERMIT_LOG(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); }

int tapfd = -1;

#define TAP_MTU 1500

typedef struct {
	uint8_t buf[TAP_MTU];
	int idx;
	int len;
	int zlp;
} tap_slot;

void tap_slot_reset(tap_slot *tslot) {
	tslot->idx = 0;
	tslot->len = 0;
	tslot->zlp = 0;
}

void tap_init(void) {
	tapfd = open("/dev/net/tun", O_RDWR);
	if (tapfd < 0) {
		perror("tap open");
		return;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	int ret;
	ret = ioctl(tapfd, TUNSETIFF, (void *)&ifr);
	if (ret < 0) {
		perror("tap ioctl");
		tapfd = -1;
		return;
	}

	KERMIT_LOG("TAP IF NAME: %s\n\r", ifr.ifr_name);
}

typedef struct {
	kermit_slot *rxslot;
	kermit_slot *txslot;
	uint8_t localsn;

	tap_slot *tap_t2k;
	tap_slot *tap_k2t;

} kermit_server_context;

static void kermit_server_reset(kermit_server_context *kctx) {
	kctx->localsn = 0;
}

static void kermit_pkt_send(kermit_slot *txslot) {
	int fd = STDOUT_FILENO;
	txslot->idx = 0;
	txslot->len = kermit_pktlen_get(txslot->buf);
	int ret;
	while(txslot->idx < txslot->len) {
		ret = write(fd, &txslot->buf[txslot->idx],
			(txslot->len - txslot->idx));
		if ((ret < 0) && (ret == EINTR)) {
			continue;
		}
		if (ret < 0) {
			perror("stdout write");
			break;
		}
		txslot->idx += ret;
	}
	const uint8_t eol[2] = { '\n', '\r' };
	write(fd, &eol[0], 2);
}

void tap_k2t_send(tap_slot *txslot) {
        int fd = tapfd;
        if (tapfd < 0) { return; }
        txslot->len = txslot->idx;
        txslot->idx = 0;
        if (txslot->len == 0) { return; }
        int ret;
        while(txslot->idx < txslot->len) {
                ret = write(fd, &txslot->buf[txslot->idx],
                        (txslot->len - txslot->idx));
                if ((ret < 0) && (ret == EINTR)) {
                        continue;
                }
                if (ret < 0) {
                        //perror("tap write");
                        continue;
                }
                txslot->idx += ret;
        }
        //KERMIT_LOG("TAP.K2T.%d.BYTES", txslot->len);
        txslot->idx = 0;
        txslot->len = 0;
}


#define MSG_BADSUM "BADSUM"
#define MSG_BADSEQ "BADSEQ"
#define MSG_RESET "KERMIT.SERVER.RESET"

static void kermit_server_rxhandle(kermit_server_context *kctx) {
	//KERMIT_LOG("SERVER.HANDLE.");
	kermit_slot *rxslot; rxslot = kctx->rxslot;
	kermit_slot *txslot; txslot = kctx->txslot;

#ifdef KERMIT_LINK_ECHO
	// detect line echo
	if (memcmp(rxslot->buf, txslot->buf,
		kermit_pktlen_get(rxslot->buf)) == 0) {
		kermit_slot_reset(kctx->rxslot);
		return;
	}
#endif

	if (kermit_pktsum_chk(rxslot->buf) == 0) {
		// badsum, drop
		kermit_pkt_make(txslot->buf, KERMIT_TYPE_NAK,
				kctx->localsn, (uint8_t *)MSG_BADSUM,
				sizeof(MSG_BADSUM));
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		return;
	}

	uint8_t remote_type;
	remote_type = rxslot->buf[KERMIT_OFFSET_TYPE];
	uint8_t remote_seq;
	remote_seq = kermit_unchar(rxslot->buf[KERMIT_OFFSET_SEQ]);

	// before seq check
	switch(remote_type) {
	case KERMIT_TYPE_BREAK:
		//KERMIT_LOG("BREAK.RESET.SERVER.");
		kermit_pkt_make(txslot->buf, KERMIT_TYPE_ACK,
			remote_seq, (uint8_t *)MSG_RESET, sizeof(MSG_RESET));
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		kermit_server_reset(kctx);
		return;
	case KERMIT_TYPE_NAK:
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		return;
	}

	uint8_t local_seq;
	int acked;
	local_seq = (kctx->localsn & ~(1 << 7));
	acked = (kctx->localsn & (1 << 7));

	if (!acked && (remote_seq == local_seq)) {
		// ack mark
		//KERMIT_LOG("SEQ.ZACK.");
		kctx->localsn |= (1 << 7);
	} else if (acked && (remote_seq == ((local_seq + 1) & KERMIT_SEQ_MASK))) {
		// new pkt
		//KERMIT_LOG("SEQ.NEW.");
		kctx->localsn = (remote_seq | (1 << 7));
	} else if (acked && (remote_seq == local_seq)) {
		//KERMIT_LOG("SEQ.DUP.");
		// dup seq, resend reply
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		return;
	} else {
		// bad seq
		//KERMIT_LOG("SEQ.BAD.%02X.%02X.", local_seq, remote_seq);
		kermit_pkt_make(txslot->buf, KERMIT_TYPE_NAK,
			kctx->localsn, (uint8_t *)MSG_BADSEQ, sizeof(MSG_BADSEQ));
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		return;
	}

	uint8_t *reply_data = NULL;
	int reply_len = 0;

	tap_slot *tap_k2t;
	tap_slot *tap_t2k;

	tap_k2t = kctx->tap_k2t;
	tap_t2k = kctx->tap_t2k;
	int enclen;
	int declen;
	int copylen;

	switch(remote_type) {
	case KERMIT_TYPE_ECHO:
		reply_len = kermit_pkt_decode_inplace(rxslot->buf);
		reply_data = &rxslot->buf[KERMIT_OFFSET_DATA];
		break;
	case KERMIT_TYPE_TAP:
		declen = kermit_pkt_decode_inplace(rxslot->buf);
		copylen = MIN(TAP_MTU - tap_k2t->idx, declen);
		memcpy(&tap_k2t->buf[tap_k2t->idx],
			&rxslot->buf[KERMIT_OFFSET_DATA], copylen);
		tap_k2t->idx += copylen;
		if (declen == 0) { tap_k2t_send(tap_k2t); }

		reply_data = &tap_t2k->buf[tap_t2k->idx];
		reply_len = tap_t2k->len - tap_t2k->idx;
                if (tap_t2k->zlp != 0) { tap_t2k->zlp = 0; reply_len = 0; }
		enclen = kermit_pkt_make(txslot->buf, KERMIT_TYPE_ACK,
					kctx->localsn, reply_data, reply_len);
		tap_t2k->idx += enclen;
                if ((tap_t2k->len != 0) && (tap_t2k->idx >= tap_t2k->len)) {
                        tap_t2k->idx = 0;
                        tap_t2k->len = 0;
                        tap_t2k->zlp = 1;
                }
		kermit_pkt_send(txslot);
		kermit_slot_reset(kctx->rxslot);
		return;
	}

	kermit_pkt_make(txslot->buf, KERMIT_TYPE_ACK,
			kctx->localsn, reply_data, reply_len);
	kermit_pkt_send(txslot);
	kermit_slot_reset(kctx->rxslot);
	return;
}

#define STDIN_RXFIFOSIZE 256

int main(void) {
	tap_init();
	int ret;
	fd_set rfds;
	struct timeval tv;
	fifo8 stdin_rxfifo;
	uint8_t stdin_rxfifobuf[STDIN_RXFIFOSIZE];
	stdin_rxfifo.data = stdin_rxfifobuf;
	stdin_rxfifo.mask = STDIN_RXFIFOSIZE - 1;
	fifo8_reset(&stdin_rxfifo);

	kermit_server_context kermit_server;
	kermit_slot kermit_server_rxslot;
	kermit_slot kermit_server_txslot;

	kermit_server.rxslot = &kermit_server_rxslot;
	kermit_server.txslot = &kermit_server_txslot;

        tap_slot tap_t2k;
        tap_slot tap_k2t;

        kermit_server.tap_t2k = &tap_t2k;
        kermit_server.tap_k2t = &tap_k2t;

	kermit_server_reset(&kermit_server);
	kermit_slot_reset(kermit_server.rxslot);
	kermit_slot_reset(kermit_server.txslot);
	tap_slot_reset(kermit_server.tap_t2k);
	tap_slot_reset(kermit_server.tap_k2t);

	kermit_server_context *kctx;
	kctx = &kermit_server;

	uint8_t stdin_rxbuf[STDIN_RXFIFOSIZE];
	unsigned int fifo_ava, fifo_used;
	ssize_t rdret;
	int i;
	while(1) {
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		if (tapfd >= 0) {
			FD_SET(tapfd, &rfds);
		}
		tv.tv_sec = 0;
		tv.tv_usec = 2000,
		ret = select(10, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}
		if (ret == 0) {
			continue;
		}
		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			fifo_ava = fifo8_num_free(&stdin_rxfifo);
			rdret = read(STDIN_FILENO, &stdin_rxbuf[0], fifo_ava);
			if (rdret < 0) {
				perror("stdin read");
				continue;
			}
			for (i = 0; i < rdret; i++) {
				fifo8_push(&stdin_rxfifo, stdin_rxbuf[i]);
			}
			fifo_used = fifo8_num_used(&stdin_rxfifo);
			while((fifo_used > 0) && (kctx->rxslot->len == 0)) {
				kermit_slot_recv(kctx->rxslot,
						fifo8_pop(&stdin_rxfifo));
				fifo_used--;
			}
		}
                if ((tapfd > 0) && FD_ISSET(tapfd, &rfds) &&
                        (tap_t2k.len == 0) && (tap_t2k.zlp == 0)) {
                        rdret = read(tapfd, &tap_t2k.buf[0], TAP_MTU);
                        if (rdret <= 0) { continue; }
                        tap_t2k.idx = 0;
                        tap_t2k.len = rdret;
                        tap_t2k.zlp = 0;
                        //KERMIT_LOG("TAP.T2K.%d.BYTES.", tap_t2k.len);
                }
		if (kctx->rxslot->len != 0) {
			kermit_server_rxhandle(kctx);
		}
	}
	
	return 0;
}

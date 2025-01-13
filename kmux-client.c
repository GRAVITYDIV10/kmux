#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <errno.h>

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

enum {
	KERMIT_STATE_RESET = (1 << 0),
	KERMIT_STATE_WAIT_ACK = (1 << 1),
	KERMIT_STATE_TIMEOUT = (1 << 2),
	KERMIT_STATE_SEND_ECHO = (1 << 3),
	KERMIT_STATE_SEND_TAP = (1 << 4),
};

typedef struct {
	uint32_t state;

	kermit_slot *rxslot;
	kermit_slot *txslot;
	uint8_t localsn;
	time_t last_time;

	tap_slot *tap_k2t;
	tap_slot *tap_t2k;

} kermit_client_context;

void kermit_client_reset(kermit_client_context *kctx) {
	kctx->state = KERMIT_STATE_RESET;
	kctx->localsn = 0;
	kctx->last_time = 0;
}

void kermit_txslot_send(kermit_client_context *kctx) {
	kermit_slot *txslot; txslot = kctx->txslot;

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
                        //perror("stdout write");
                        break;
                }
                txslot->idx += ret;
        }
        const uint8_t eol[2] = { '\n', '\r' };
        write(fd, &eol[0], 2);
	kctx->last_time = time(NULL);
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
                        perror("tap write");
                        break;
                }
                txslot->idx += ret;
        }
	//KERMIT_LOG("TAP.K2T.%d.BYTES", txslot->len);
	txslot->idx = 0;
	txslot->len = 0;
}

#define KERMIT_TIMEOUT 1

void kermit_client_state_machine(kermit_client_context *kctx) {
	//KERMIT_LOG("CLIENT.HANDLE.");
	kermit_slot *rxslot; rxslot = kctx->rxslot;
	kermit_slot *txslot; txslot = kctx->txslot;

	if ((time(NULL) - kctx->last_time) > KERMIT_TIMEOUT) {
		kctx->state |= KERMIT_STATE_TIMEOUT;
	}

	if (rxslot->len != 0) {
		kctx->last_time = time(NULL);
#ifdef KERMIT_LINK_ECHO
		// detect line echo
		if (memcmp(rxslot->buf, txslot->buf,
			kermit_pktlen_get(rxslot->buf)) == 0) {
			kermit_slot_reset(kctx->rxslot);
		}
#endif
	}

	if (kctx->state & KERMIT_STATE_RESET) {
		KERMIT_LOG("CLIENT.RESET.");
		kermit_client_reset(kctx);
		kermit_pkt_make(txslot->buf, KERMIT_TYPE_BREAK,
				kctx->localsn, NULL, 0);
		kermit_txslot_send(kctx);
		kermit_slot_reset(kctx->rxslot);
		kctx->state ^= KERMIT_STATE_RESET;
		kctx->state |= KERMIT_STATE_WAIT_ACK;
		return;
	}

	if (kctx->state & KERMIT_STATE_TIMEOUT) {
		KERMIT_LOG("TIMEOUT.");
		kermit_txslot_send(kctx);
		kctx->state ^= KERMIT_STATE_TIMEOUT;
		return;
	}


	static uint8_t echobuf[KERMIT_PKT_MAXSIZE];
	static int echolen = 0;
	int i;

	if (kctx->state & KERMIT_STATE_SEND_ECHO) {
		//KERMIT_LOG("ECHO.");
		for (i = 0; i < echolen; i++) {
			echobuf[i] = rand();
		}
		echolen = kermit_pkt_make(txslot->buf, KERMIT_TYPE_ECHO,
				kctx->localsn, echobuf, rand());
		kermit_txslot_send(kctx);
		kermit_slot_reset(kctx->rxslot);
		kctx->state ^= KERMIT_STATE_SEND_ECHO;
		kctx->state |= KERMIT_STATE_WAIT_ACK;
		return;
	}

	tap_slot *tap_t2k;
	tap_t2k = kctx->tap_t2k;

	int sended;
	uint8_t *payload = NULL;
	int payload_size = 0;
	if (kctx->state & KERMIT_STATE_SEND_TAP) {
		payload = &tap_t2k->buf[tap_t2k->idx];
		payload_size = tap_t2k->len - tap_t2k->idx;
		if (tap_t2k->zlp != 0) { tap_t2k->zlp = 0; payload_size = 0; }
		sended = kermit_pkt_make(txslot->buf, KERMIT_TYPE_TAP,
			kctx->localsn, payload, payload_size);
		tap_t2k->idx += sended;
		if ((tap_t2k->len != 0) && (tap_t2k->idx >= tap_t2k->len)) {
			tap_t2k->idx = 0;
			tap_t2k->len = 0;
			tap_t2k->zlp = 1;
		}
		kermit_txslot_send(kctx);
		kermit_slot_reset(kctx->rxslot);
		kctx->state ^= KERMIT_STATE_SEND_TAP;
		kctx->state |= KERMIT_STATE_WAIT_ACK;
		return;
	}

	if (kctx->state & KERMIT_STATE_WAIT_ACK) {
		if (rxslot->len == 0) { return; }
		//KERMIT_LOG("WAIT.ACK.");
		uint8_t remote_type;
		remote_type = rxslot->buf[KERMIT_OFFSET_TYPE];
		uint8_t remote_seq;
		remote_seq = kermit_unchar(rxslot->buf[KERMIT_OFFSET_SEQ]);
		uint8_t local_seq;
		local_seq = kctx->localsn;
		if ((remote_seq != local_seq) || (remote_type != KERMIT_TYPE_ACK)) {
			kermit_txslot_send(kctx);
			kermit_slot_reset(kctx->rxslot);
			return;
		}
		uint8_t local_type;
		local_type = txslot->buf[KERMIT_OFFSET_TYPE];

		switch(local_type) {
		case KERMIT_TYPE_BREAK:
			break;
		default:
			kctx->localsn = (kctx->localsn + 1) & KERMIT_SEQ_MASK;
			break;
		}

		int declen;
		declen = kermit_pkt_decode_inplace(rxslot->buf);

		tap_slot *tap_k2t;
		tap_k2t = kctx->tap_k2t;

		int copylen;
		switch(local_type) {
		case KERMIT_TYPE_ECHO:
			if ((declen != echolen) ||
				(memcmp(&rxslot->buf[KERMIT_OFFSET_DATA],
					echobuf, declen) != 0)) {
				KERMIT_LOG("ECHO.FAULT");
			}
			break;
		case KERMIT_TYPE_TAP:
			copylen = MIN((TAP_MTU - tap_k2t->idx), declen);
			memcpy(&tap_k2t->buf[tap_k2t->idx],
				&rxslot->buf[KERMIT_OFFSET_DATA],
				copylen);
			tap_k2t->idx += copylen;
			if (declen == 0) { tap_k2t_send(tap_k2t); }
			break;
		}

		//KERMIT_LOG("%02X.", kctx->localsn);
		static int next = 0;
		next++;
		switch(next % 2) {
		case 1:
			//kctx->state |= KERMIT_STATE_SEND_ECHO;
			//break;
		default:
			kctx->state |= KERMIT_STATE_SEND_TAP;
			break;
		}
		kctx->state ^= KERMIT_STATE_WAIT_ACK;
		return;
	}
}

#define STDIN_RXFIFOSIZE 256

int main(void) {
	int ret;
	tap_init();

	fd_set rfds;
	struct timeval tv;

        fifo8 stdin_rxfifo;
        uint8_t stdin_rxfifobuf[STDIN_RXFIFOSIZE];
        stdin_rxfifo.data = stdin_rxfifobuf;
        stdin_rxfifo.mask = STDIN_RXFIFOSIZE - 1;
        fifo8_reset(&stdin_rxfifo);

        kermit_client_context kermit_client;
	memset(&kermit_client, 0, sizeof(kermit_client));
        kermit_slot kermit_client_rxslot;
        kermit_slot kermit_client_txslot;
	tap_slot tap_t2k;
	tap_slot tap_k2t;

        kermit_client.rxslot = &kermit_client_rxslot;
        kermit_client.txslot = &kermit_client_txslot;
	kermit_client.tap_t2k = &tap_t2k;
	kermit_client.tap_k2t = &tap_k2t;

        kermit_client_reset(&kermit_client);
        kermit_slot_reset(kermit_client.rxslot);
        kermit_slot_reset(kermit_client.txslot);
	tap_slot_reset(kermit_client.tap_t2k);
	tap_slot_reset(kermit_client.tap_k2t);

        kermit_client_context *kctx;
	kctx = &kermit_client;

	ssize_t rdret;
	int i;

	uint8_t stdin_rxbuf[STDIN_RXFIFOSIZE];
	int fifo_ava, fifo_used;
	srand(time(NULL));

	while(1) {
		kermit_client_state_machine(kctx);

		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		if (tapfd > 0) {
			FD_SET(tapfd, &rfds);
		}
		tv.tv_sec = 0;
		tv.tv_usec = 2000,
		ret = select(10, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}
		if (ret == 0) { continue; }
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
	}

	return 0;
}

#include "kermit.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

static void encode_file(FILE *fpin, FILE *fpout) {
	uint8_t inbuf[BUFSIZ];
	size_t inidx;
	size_t inlen;
	uint8_t pktout[KERMIT_PKT_MAXSIZE];
	int ret;

	int8_t seq = 0;

	kermit_pkt_make(&pktout[0], KERMIT_TYPE_FHDR, seq, NULL, 0);
	seq = (seq + 1) & KERMIT_SEQ_MASK;
	fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
	fprintf(fpout, "\n\r");

	while(feof(fpin) == 0) {
		inidx = 0;
		inlen = fread(inbuf, 1, BUFSIZ, fpin);
		while (inidx < inlen) {
			ret = kermit_pkt_make(&pktout[0],
					KERMIT_TYPE_DATA,
					seq, &inbuf[inidx], (inlen - inidx));
			seq = (seq + 1) & KERMIT_SEQ_MASK;
			inidx += ret;
			fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
			fprintf(fpout, "\n\r");
			// test seq dup 
			//fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
			//fprintf(fpout, "\n\r");
			// test bad packet
			//pktout[KERMIT_OFFSET_DATA] = ' ';
			//fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
			//fprintf(fpout, "\n\r");
			// test seq bad
			//pktout[KERMIT_OFFSET_SEQ] =
				//kermit_tochar((seq - 1) & KERMIT_SEQ_MASK);
			//kermit_pktsum_update(pktout);
			//fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
			//fprintf(fpout, "\n\r");
		}
	}

	kermit_pkt_make(&pktout[0], KERMIT_TYPE_EOF, seq, NULL, 0);
	seq = (seq + 1) & KERMIT_SEQ_MASK;
	fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
	fprintf(fpout, "\n\r");

	kermit_pkt_make(&pktout[0], KERMIT_TYPE_BREAK, seq, NULL, 0);
	seq = (seq + 1) & KERMIT_SEQ_MASK;
	fwrite(pktout, 1, kermit_pktlen_get(pktout), fpout);
	fprintf(fpout, "\n\r");

	fflush(fpout);
}

static void decode_file(FILE *fpin, FILE *fpout) {
	kermit_slot r_slot;
	kermit_slot *rxslot;
	rxslot = &r_slot;
	kermit_slot_reset(rxslot);

	int localsn = 0;
	int remotesn = 0;
	int acked = 0;

	int remotetype = 0;
	int declen;
	while(feof(fpin) == 0) {
		kermit_slot_recv(rxslot, fgetc(fpin));
		if (rxslot->len == 0) { continue; }
		if (kermit_pktsum_chk(rxslot->buf) == 0) {
			kermit_slot_reset(rxslot);
			continue;
		}
		remotesn = kermit_unchar(rxslot->buf[KERMIT_OFFSET_SEQ]);
		if (!acked && (localsn == remotesn)) {
			acked = 1;
		} else if (acked && (localsn == remotesn)) {
			// dup, ignore
			//fprintf(stderr, "DUPSEQ.");
			kermit_slot_reset(rxslot);
			continue;
		} else if (acked &&
			(remotesn == ((localsn + 1) & KERMIT_SEQ_MASK))) {
			// new
			localsn = remotesn;
		} else {
			// bad, ignore
			//fprintf(stderr, "BADSEQ.");
			kermit_slot_reset(rxslot);
			continue;
		}
		remotetype = rxslot->buf[KERMIT_OFFSET_TYPE];
		switch (remotetype) {
		case 'D':
			declen = kermit_pkt_decode_inplace(rxslot->buf);
			//fprintf(stderr, "%d.", declen);
			fwrite(&rxslot->buf[KERMIT_OFFSET_DATA], 1, declen, fpout);
			break;
		default:
			//fprintf(stderr, "TYPEUNHANDLE.");
			// unhandle
			break;
		}
		kermit_slot_reset(rxslot);
	}
	fflush(fpout);
}

static void translate_table(void) {
	int i;
	int enclen;
	uint8_t encbuf[KERMIT_ENC_MAXSIZE];
	printf("DATA ELEN ENC0 ENC1 ENC2 ");
#ifdef KERMIT_LINK_CTRL
#ifdef KERMIT_LINK_7BIT
	printf("PRINTABLE ");
#endif
#endif
	printf("\n\r");
	uint8_t decbuf[1];
	for (i = 0; i <= 0xFF; i++) {
		encbuf[0] = encbuf[1] = encbuf[2] = 0;
		enclen = kermit_encode((uint8_t *)&i, &encbuf[0]);
		printf("%02X   %02X   %02X   %02X   %02X   ",
			i, enclen, encbuf[0], encbuf[1], encbuf[2]);
#ifdef KERMIT_LINK_CTRL
#ifdef KERMIT_LINK_7BIT
		printf("%c%c%c ", encbuf[0], encbuf[1], encbuf[2]);
#endif
#endif
		printf("\n\r");
		kermit_decode(&encbuf[0], &decbuf[0]);
		if (decbuf[0] != i) {
			printf("!!!DECODE FAIL %02X!!!\n\r", decbuf[0]);
			break;
		}
	}
}

static void usage_print(char *arg0) {
	fprintf(stderr, "usage: %s [-options] < infile > outfile", arg0);
	fprintf(stderr, "options:\n\r");
	fprintf(stderr, " -e encode\n\r");
	fprintf(stderr, " -d decode\n\r");
	fprintf(stderr, " -t print translate table\n\r");
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		usage_print(argv[0]);
		exit(EXIT_FAILURE);
	}

	switch(argv[1][1]) {
	case 'e':
		encode_file(stdin, stdout);
		break;
	case 'd':
		decode_file(stdin, stdout);
		break;
	case 't':
		translate_table();
		break;
	default:
		usage_print(argv[0]);
		exit(EXIT_FAILURE);
	}

	return 0;
};
